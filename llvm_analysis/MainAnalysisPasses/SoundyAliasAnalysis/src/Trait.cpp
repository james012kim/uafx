#include "Trait.h"

namespace DRCHECKER {
    std::map<int, std::map<void*,std::set<TraitCheck*>>> TraitCheck::dir;

    TraitCheck *TraitCheck::getTraitCheck(int pat, int ty, VAL val) {
        // TODO: Any sanity checks regarding the passed-in parameters?
        if (ty == ET_DEF) {
            // Unify the default values in these cases.
            memset(&val,0,sizeof(val));
        }
        void *k_val = (void *)val.v;
        if (ty == ET_CONST) {
            k_val = (void *)(uint64_t)val.n;
        } else if (ty == ET_CONST_SET) {
            //For the switch-case TraitCheck, we will always create a new instance.
            k_val = (void*)val.cset;
        } else if (ty == ET_CONST_BM) {
            //Same as above.
            k_val = (void*)val.n_bm;
        }
        std::set<TraitCheck *> &tcs = dir[ty][k_val];
        for (TraitCheck *tc : tcs) {
            if (tc->pat == pat) {
                return tc;
            }
        }
        // No existing instance found, create a new one.
        TraitCheck *newTc = new TraitCheck(pat, ty, val);
        tcs.insert(newTc);
        return newTc;
    }

    // Convert a LLVM cmp predicate to a TraitCheck pattern.
    int TraitCheck::getTCPattern(CmpInst::Predicate &pred, bool reverse) {
        switch (pred) {
            case CmpInst::Predicate::FCMP_OEQ:
            case CmpInst::Predicate::FCMP_UEQ:
            case CmpInst::Predicate::ICMP_EQ:
                return TraitCheck::PT_EQ;
            case CmpInst::Predicate::FCMP_OGT:
            case CmpInst::Predicate::FCMP_UGT:
            case CmpInst::Predicate::ICMP_UGT:
            case CmpInst::Predicate::ICMP_SGT:
                return (reverse ? TraitCheck::PT_LT : TraitCheck::PT_GT);
            case CmpInst::Predicate::FCMP_OGE:
            case CmpInst::Predicate::FCMP_UGE:
            case CmpInst::Predicate::ICMP_UGE:
            case CmpInst::Predicate::ICMP_SGE:
                return (reverse ? TraitCheck::PT_LE : TraitCheck::PT_GE);
            case CmpInst::Predicate::FCMP_OLT:
            case CmpInst::Predicate::FCMP_ULT:
            case CmpInst::Predicate::ICMP_ULT:
            case CmpInst::Predicate::ICMP_SLT:
                return (reverse ? TraitCheck::PT_GT : TraitCheck::PT_LT);
            case CmpInst::Predicate::FCMP_OLE:
            case CmpInst::Predicate::FCMP_ULE:
            case CmpInst::Predicate::ICMP_ULE:
            case CmpInst::Predicate::ICMP_SLE:
                return (reverse ? TraitCheck::PT_GE : TraitCheck::PT_LE);
            case CmpInst::Predicate::FCMP_ONE:
            case CmpInst::Predicate::FCMP_UNE:
            case CmpInst::Predicate::ICMP_NE:
                return TraitCheck::PT_NE;
            case CmpInst::Predicate::FCMP_TRUE:
                break;
            case CmpInst::Predicate::FCMP_FALSE:
                break;
            case CmpInst::Predicate::FCMP_ORD:
                break;
            case CmpInst::Predicate::FCMP_UNO:
                break;
            default:
                break;
        }
        return TraitCheck::PT_DEF;
    }

    z3::expr TraitCheck::getZ3Expr4Branch(unsigned dst, int &ec) {
        ec = 0;
        expr v = get_z3v();
        if (this->ty == ET_CONST) {
            if (dst > 1) {
                goto err;
            }
            int nc = this->val.n;
            switch (this->pat) {
            case PT_EQ:
                return dst ? v != z3c.bv_val(nc, 64) : v == z3c.bv_val(nc, 64);
            case PT_NE:
                return dst ? v == z3c.bv_val(nc, 64) : v != z3c.bv_val(nc, 64);
            case PT_GT:
                return dst ? v <= z3c.bv_val(nc, 64) : v > z3c.bv_val(nc, 64);
            case PT_GE:
                return dst ? v < z3c.bv_val(nc, 64) : v >= z3c.bv_val(nc, 64);
            case PT_LT:
                return dst ? v >= z3c.bv_val(nc, 64) : v < z3c.bv_val(nc, 64);
            case PT_LE:
                return dst ? v > z3c.bv_val(nc, 64) : v <= z3c.bv_val(nc, 64);
            default:
                goto err;
            }
        }
        if (this->ty == ET_CONST_SET) {
            //switch-case TraitCheck.
            if (!this->val.cset || dst > this->val.cset->size()) {
                goto err;
            }
            if (dst < this->val.cset->size()) {
                //The target is a normal switch-case.
                return v == z3c.bv_val(this->val.cset->at(dst), 64);
            } else {
                //The target is the "default" switch-case.
                z3::expr e(z3c);
                for (int i = 0; i < this->val.cset->size(); ++i) {
                    expr se = (v != z3c.bv_val(this->val.cset->at(i), 64));
                    if (i == 0) {
                        e = se;
                    } else {
                        e = e && se;
                    }
                }
                return e;
            }
        }
err:
        ec = -1;
        return v;
    }

    bool TraitCheck::isContMasked(unsigned &st, unsigned &len) {
        if (this->ty != TraitCheck::ET_CONST_BM || !this->val.n_bm) {
            return false;
        }
        uint64_t mask = this->val.n_bm->mask;
        unsigned width = this->val.n_bm->width;
        int start = -1, last = -1;
        for (unsigned i = 0; i < width; ++i) {
            if (mask & 1) {
                if (start < 0) {
                    //This bit starts the mask range.
                    start = last = i;
                } else if (i == last + 1) {
                    //Still continuous.
                    ++last;
                } else {
                    //The "1" range is not cotinuous.
                    return false;
                }
            }
            mask >>= 1;
        }
        st = start;
        len = (last - start + 1);
        return true;
    }

    bool TraitCheck::constantCheckFail(int ns, int nc, bool true_br) {
        switch (this->pat) {
            case TraitCheck::PT_EQ:
                return (ns != nc) == true_br;
            case TraitCheck::PT_NE:
                return (ns == nc) == true_br;
            case TraitCheck::PT_GT:
                return (ns <= nc) == true_br;
            case TraitCheck::PT_GE:
                return (ns < nc) == true_br;
            case TraitCheck::PT_LT:
                return (ns >= nc) == true_br;
            case TraitCheck::PT_LE:
                return (ns > nc) == true_br;
            default:
                return false;
        }
        return false;
    }

    std::map<int,std::map<int,std::set<TraitSet*>>> TraitSet::dir;

    TraitSet *TraitSet::getTraitSet(int pat, int n, int op) {
        // First regularize the parameters.
        if (pat == PT_DEF || pat == PT_VAR) {
            // No need for constant parameter in these cases.
            n = 0;
        }
        if (pat != PT_ADJ) {
            // No need for an operator in these cases.
            op = OP_DEF;
        }
        // Search for the existing instance matching the provided arguments.
        if (dir.find(pat) != dir.end() && dir[pat].find(n) != dir[pat].end()) {
            for (TraitSet *currTraitSet : dir[pat][n]) {
                if (currTraitSet->op == op) {
                    return currTraitSet;
                }
            }
        }
        // Unseen pattern, create a new instance.
        TraitSet *newTraitSet = new TraitSet(pat, n, op);
        dir[pat][n].insert(newTraitSet);
        return newTraitSet;
    }

    bool TraitSet::kill(TraitCheck *tc, unsigned dst) {
        if (!tc) {
            return false;
        }
        bool true_br = (dst == 0);
        if (tc->ty == TraitCheck::ET_CONST) {
            int nc = tc->val.n;
            if (this->pat == PT_CONST) {
                int ns = this->n;
                //Current situation: the check is comparing with a constant "nc", with the
                //operator "tc->pat", while the set is to assign the constant "ns".
                return tc->constantCheckFail(ns,nc,true_br);
            }
            // TODO: consider other set patterns besides PT_CONST.
        } else if (tc->ty == TraitCheck::ET_CONST_SET) {
            //The check is a switch-case.
            //First decide which switch-case will the TraitSet lead to..
            if (!tc->val.cset || this->pat != PT_CONST) {
                return false;
            }
            unsigned s_tgt = 0;
            int ns = this->n;
            for (; s_tgt < tc->val.cset->size(); ++s_tgt) {
                if (tc->val.cset->at(s_tgt) == ns) {
                    break;
                }
            }
            return (s_tgt != dst);
        } else if (tc->ty == TraitCheck::ET_CONST_BM) {
            if (!tc->val.n_bm) {
                return false;
            }
            //For now we only handle the cases where the masked bits
            //in TraitCheck are continuous.
            //TODO: though less likely, what if it's not continuous?
            unsigned m_st = 0, m_len = 0;
            if (!tc->isContMasked(m_st,m_len)) {
                return false;
            }
            unsigned nc = tc->val.n_bm->n;
            //Then we need to know whether and how the TraitSet can affect
            //this continuous bit range.
            //For now we require that the set must completely cover
            //the masked bit range (e.g., AND cannot only clear a part
            //of bits in the masked range).
            //TODO: we may need to lift the above restriction later and
            //support more complex cases.
            unsigned ns = 0;
            if (!this->writeBitRange(m_st,m_len,ns)) {
                return false;
            }
            ns <<= m_st;
            //Now compare the "ns" (result value after set and AND) and
            //"nc" (compare-against value).
            return tc->constantCheckFail(ns,nc,true_br);
        }
        // TODO: handle other comparison types aside ET_CONST, e.g., if the
        // variable (Value*) used in the check and set are the same, we may
        // still do the killer match.
        return false;
    }

    bool TraitSet::writeBitRange(unsigned st, unsigned len, unsigned &res) {
        //Some sanity checks.
        //TODO: the check should be based on the actual value type.
        if (st >= 128 || len > 128 || !len) {
            return false;
        }
        int n = this->n;
        n >>= st;
        n &= ((1 << len) - 1);
        if (this->pat == PT_CONST) {
            res = n;
            return true;
        } else if (this->pat == PT_ADJ) {
            if (this->op == OP_AND) {
                //See whether all bits in the range are cleared by the AND.
                //"this->n" is the bit mask used by the AND, so basically we will
                //see whether the bits in range in "n" are all zero.
                if (!n) {
                    res = 0;
                    return true;
                }
            } else if (this->op == OP_OR) {
                //Similar to above, but this time we need to ensure all bits
                //are non-zero.
                if (n + 1 == 1 << len) {
                    res = n;
                    return true;
                }
            }
        }
        return false;
    }
}