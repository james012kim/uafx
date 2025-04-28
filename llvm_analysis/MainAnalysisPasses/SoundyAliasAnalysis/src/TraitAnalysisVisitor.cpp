#include "TraitAnalysisVisitor.h"

using namespace llvm;

namespace DRCHECKER {

#define DEBUG_VISIT_SWITCH_INST
#define DEBUG_VISIT_BRANCH_INST
#define DEBUG_VISIT_STORE_INST
#define DEBUG_CALL_INST

//Assume "c" is a bit mask used in a bit operation like AND,
//extract the bitmask and its width.
int _getBitMask(Constant *c, uint64_t &mask, unsigned &width) {
    if (!c || !dyn_cast<ConstantInt>(c)) {
        return 0;
    }
    int64_t smask;
    uint64_t umask;
    if (!InstructionUtils::getConstantValue(c, &smask, &umask)) {
        return 0;
    }
    mask = umask;
    width = c->getType()->getScalarSizeInBits();
    return 1;
}

//Assume "ci" is a bitmask used in an AND inst, decide which bits
//will be cleared.
int _get0bitLocs(Constant *c, std::set<unsigned> &res) {
    uint64_t mask = 0;
    unsigned width = 0;
    if (!_getBitMask(c,mask,width)) {
        return 0;
    }
    for (unsigned i = 0; i < width; ++i) {
        if (!(mask & 1)) {
            res.insert(i);
        }
        mask >>= 1;
    }
    return 1;
}

// For a 2-operand User that has exactly one constant op and one variable op,
// decide which operand is which and return.  
int _getCAndV(User *u, Value **v, Constant **c, bool *is_reverse, bool strip = true) {
    if (!u || u->getNumOperands() != 2) {
        return 0;
    }
    Value *v0 = u->getOperand(0);
    Value *v1 = u->getOperand(1);
    if (strip) {
        v0 = InstructionUtils::stripAllCasts(v0, false);
        v1 = InstructionUtils::stripAllCasts(v1, false);
    }
    if (!v0 || !v1) {
        return 0;
    }
    if ((!dyn_cast<Constant>(v0)) == (!dyn_cast<Constant>(v1))) {
        return 0;
    }
    if (v) {
        *v = dyn_cast<Constant>(v0) ? v1 : v0;
    }
    if (c) {
        *c = dyn_cast<Constant>(v0) ? dyn_cast<Constant>(v0) : dyn_cast<Constant>(v1);
    }
    if (is_reverse) {
        *is_reverse = (dyn_cast<Constant>(v0) ? true : false);
    }
    return 1;
}

// Figure out the update pattern pattern of an object field.
void TraitAnalysisVisitor::visitStoreInst(StoreInst &I) {
#ifdef TIMING
    auto t0 = InstructionUtils::getCurTime();
#endif
    // Get the dst pointer of the "store".
    Value *dstPointer = I.getPointerOperand();
    // We assume the trait analysis pass is after the alias analysis, where the pointer
    // strip/cast stuff has been properly handled and the pto records are set up.
    std::set<PointerPointsTo *> *dstPointsTo = PointsToUtils::getPointsToObjects(
        this->currState,
        this->ctx,
        dstPointer);
    if (dstPointsTo == nullptr || dstPointsTo->size() == 0) {
        // No pto records for the store target pointer.
        return;
    }
    // Collect the obj|field as targets of this store.
    std::set<std::pair<long, AliasObject *>> targetObjects;
    for (PointerPointsTo *pto : *dstPointsTo) {
        AliasObject *obj = pto->targetObject;
        if (!obj) {
            continue;
        }
        long fid = pto->dstfieldId;
        auto to_check = std::make_pair(fid, obj);
        targetObjects.insert(to_check);
    }
    // Analyze the update pattern.
    if (!targetObjects.empty()) {
        TraitSet *ts = this->getStorePattern(I);
        InstLoc *loc = InstLoc::getLoc(&I, this->ctx);
        assert(loc);
        if (ts) {
            // Record the update pattern to the target objects.
#ifdef DEBUG_VISIT_STORE_INST
            dbgs() << "TraitAnalysisVisitor::visitStoreInst(): identify TraitSet: ";
            ts->print(dbgs(), false);
            dbgs() << ", for obj|field: ";
            for (auto &pair : targetObjects) {
                dbgs() << (const void*)pair.second << "|" << pair.first << " ";
            }
            dbgs() << " @ ";
            loc->print_light(dbgs(),true);
#endif
            for (auto &pair : targetObjects) {
                long fid = pair.first;
                AliasObject *obj = pair.second;
                obj->addTraitSet(fid, ts, loc);
            }
        }
    }
#ifdef TIMING
    dbgs() << "[TIMING] TraitAnalysisVisitor::visitStoreInst(): ";
    InstructionUtils::getTimeDuration(t0, &dbgs());
#endif
    return;
}

// Analyze the update pattern of a store inst.
TraitSet *TraitAnalysisVisitor::getStorePattern(StoreInst &I) {
    // Already analyzed?
    if (this->currState.updatePatterns.find(&I) != this->currState.updatePatterns.end()) {
        return this->currState.updatePatterns[&I];
    }
    // Ok now performing the analysis.
    TraitSet *ts = nullptr;
    // Get the value to store and strip all casts.
    Value *v = I.getValueOperand();
    v = InstructionUtils::stripAllCasts(v, false);
    if (!v) {
        dbgs() << "!!! TraitAnalysisVisitor::getStorePattern(): "
               << "null src value after striping: "
               << InstructionUtils::getValueStr(&I) << "\n";
    }
    // Is it a constant assignment?
    else if (dyn_cast<llvm::Constant>(v)) {
        // A direct assignment.
        int64_t si;
        uint64_t ui;
        int r = InstructionUtils::getConstantValue(dyn_cast<llvm::Constant>(v),
                                                   &si, &ui);
        if (!r) {
            //"v" is a constant but we cannot convert it to a number?
            // TODO: handle this case.
            dbgs() << "!!! TraitAnalysisVisitor::getStorePattern(): "
                   << "cannot convert constant to number: "
                   << InstructionUtils::getValueStr(v) << "\n";
            ts = TraitSet::getTraitSet(TraitSet::PT_CONST_UNK);
        } else {
            // TODO: ui vs. si?
            ts = TraitSet::getTraitSet(TraitSet::PT_CONST, si);
        }
    }
    // Ok, it's not an constant assignment, so is it a self adjustment like i++?
    else if (InstructionUtils::isSelfStore(&I)) {
        // A self-store, but we still need to figure out what exactly the
        // modification is, e.g., i++? i+=2? i*=3?
        // TODO: get more formulas.
        if (dyn_cast<BinaryOperator>(v)) {
            BinaryOperator *bop = dyn_cast<BinaryOperator>(v);
            Constant *bc = nullptr;
            uint64_t mask = -1;
            unsigned width = 0;
            if (_getCAndV(dyn_cast<User>(bop), nullptr, &bc, nullptr, true) &&
                _getBitMask(bc, mask, width)) {
                if (bop->getOpcode() == Instruction::BinaryOps::And) {
                    ts = TraitSet::getTraitSet(TraitSet::PT_ADJ, mask, TraitSet::OP_AND);
                } else if (bop->getOpcode() == Instruction::BinaryOps::Or) {
                    ts = TraitSet::getTraitSet(TraitSet::PT_ADJ, mask, TraitSet::OP_OR);
                }
            }
        }
        if (!ts) {
            ts = TraitSet::getTraitSet(TraitSet::PT_ADJ);
        }
    }
    // Treat remaining cases as general variable store.
    // TODO: create a PT_VAR TraitSet or just ignore?
    // ts = TraitSet::getTraitSet(TraitSet::PT_VAR);
    // Update the cache and return.
    this->currState.updatePatterns[&I] = ts;
    return ts;
}

VisitorCallback *TraitAnalysisVisitor::visitCallInst(CallInst &I, Function *targetFunction,
                                                     CallContext *oldCtx,
                                                     CallContext *currCtx) {
    // Skip if this is a kernel internal function w/o a function body.
    if (targetFunction->isDeclaration()) {
        // this->handleKernelInternalFunction(I, currFunc);
        return nullptr;
    }
    // create a new ModAnalysisVisitor
    TraitAnalysisVisitor *vis = new TraitAnalysisVisitor(currState, targetFunction, currCtx);
    return vis;
}

void TraitAnalysisVisitor::_visitBranchInst(BranchInst &I) {
    //Get the check pattern and variable.
    std::pair<TraitCheck*,Value*> *chk = this->getBrChkPattern(I);
    if (!chk || !chk->first || !chk->second) {
#ifdef DEBUG_VISIT_BRANCH_INST
        dbgs() << "TraitAnalysisVisitor::visitBranchInst(): no TraitCheck for: "
        << InstructionUtils::getValueStr(&I) << "\n";
#endif
        return;
    }
    TraitCheck *tc = chk->first;
    Value *v = chk->second;
    //Now track the origin of the checked variable.
    std::map<void*, std::set<long>> res;
    int orig = this->traceCondOrigin(v, res);
    if (!res.empty()) {
        InstLoc *loc = InstLoc::getLoc(&I, this->ctx);
        assert(loc);
#ifdef DEBUG_VISIT_BRANCH_INST
        dbgs() << "TraitAnalysisVisitor::visitBranchInst(): identify TraitCheck: ";
        tc->print(dbgs(), false);
        dbgs() << " @ ";
        loc->print_light(dbgs(), true);
#endif
        if (orig == 1) {
            // Add the TCs to the origin obj|fid.
#ifdef DEBUG_VISIT_BRANCH_INST
            dbgs() << "TraitAnalysisVisitor::visitBranchInst(): add the TC to: ";
#endif
            for (auto &e : res) {
                AliasObject *obj = (AliasObject*)e.first;
                for (long fid : e.second) {
#ifdef DEBUG_VISIT_BRANCH_INST
                    dbgs() << (const void *)obj << "|" << fid << ", ";
#endif
                    this->currState.addTraitCheck(loc, obj, fid, tc);
                }
            }
#ifdef DEBUG_VISIT_BRANCH_INST
            dbgs() << "\n";
#endif
        } else if (orig == 2) {
            // Record the TC and the origin return vaue.
            CallInst *ci = (CallInst*)(res.begin()->first);
            assert(dyn_cast<CallInst>(ci));
            this->currState.addTraitCheckRet(loc, ci, tc);
        } else if (orig == 3) {
            // Record the TC and the origin phi node.
            PHINode *pi = (PHINode *)(res.begin()->first);
            assert(dyn_cast<PHINode>(pi));
            this->currState.addTraitCheckPHI(loc, pi, tc);
        }
    }
    return;
}

// Try to get the read pattern of the GV in the branch condition, e.g., a == 0 or a > 1?
void TraitAnalysisVisitor::visitBranchInst(BranchInst &I) {
#ifdef TIMING
    auto t0 = InstructionUtils::getCurTime();
#endif
    this->_visitBranchInst(I);
#ifdef TIMING
    dbgs() << "[TIMING] TraitAnalysisVisitor::visitBranchInst(): ";
    InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
    return;
}

std::pair<TraitCheck*,Value*> *TraitAnalysisVisitor::getBrChkPattern(BranchInst &I) {
    if (this->currState.checkPatterns.find(&I) != this->currState.checkPatterns.end()) {
        return &(this->currState.checkPatterns[&I]);
    }
    //Pre fill the cache.
    auto &e = this->currState.checkPatterns[&I];
    e.first = nullptr;
    e.second = nullptr;
    // Try to identify the condition pattern.
    // The general pattern we handle:
    //<cond> = cmp ......
    // br i1 <cond>, label <true>, label <false>
    if (!I.isConditional()) {
        return nullptr;
    }
    Value *condition = I.getCondition();
    if (!condition || !dyn_cast<CmpInst>(condition)) {
        return nullptr;
    }
    CmpInst *cmpInst = dyn_cast<CmpInst>(condition);
    CmpInst::Predicate pred = cmpInst->getPredicate();
    // We now only consider the case: one op is a variable directly loaded from an obj|field,
    // and the other is a constant.
    // TODO: (1) a variable may be loaded, and then undergoes some calculation, e.g., *p+1<2.
    // TODO: (2) if two operands are both constants, instanly evaluate the condition and
    // branch feasibility? (this is less likely due to the compiler optimization).
    // TODO: (3) if two operands are both variables, what should we do? (e.g., look at the
    // store with the same variable?).
    Value *v = nullptr;
    Constant *c = nullptr;
    bool is_reverse = false;
    if (!_getCAndV(dyn_cast<User>(cmpInst),&v,&c,&is_reverse,true)) {
        return nullptr;
    }
    assert(v && c);
    // First get the integer value of the constant.
    int64_t si;
    uint64_t ui;
    if (!InstructionUtils::getConstantValue(c, &si, &ui)) {
        // This should be less likely.
        return nullptr;
    }
    // Record and strip the bitmask operation used to check a single bit in the
    // variable (e.g., if (v & 1)).
    // We currently support simple patterns like below:
    //  %144 = load i8, i8* %143
    //  %145 = and i8 %144, 1
    //  %146 = icmp eq i8 %145, 0
    // TODO: there may exist more complex cases (e.g., involving bit shift).
    uint64_t mask = -1;
    unsigned mask_width = 0;
    if (dyn_cast<BinaryOperator>(v)) {
        BinaryOperator *bop = dyn_cast<BinaryOperator>(v);
        if (bop->getOpcode() == Instruction::BinaryOps::And) {
            Constant *bc = nullptr;
            if (!_getCAndV(dyn_cast<User>(bop),&v,&bc,nullptr,true)) {
                //The "v" in the cmp is from an AND inst, but we cannot
                //extract the bitmask, in this case continuing tracing
                //the origin of "v" is meaningless because we cannot
                //generate the correct TraitCheck anyway.
                return nullptr;
            }
            assert(v && bc);
            if (!_getBitMask(bc,mask,mask_width)) {
                //Cannot get the bit mask.
                return nullptr;
            }
        }
    }
    // Reaching here, we either have a bitmask (width != 0) or not
    // (no AND involved in the check).
    // Construct the TraitCheck instance.
    int pt = TraitCheck::getTCPattern(pred, is_reverse);
    int et = TraitCheck::ET_CONST;
    TraitCheck::VAL val;
    if (!mask_width) {
        // A normal constant check.
        val.n = si;
    } else {
        // A bit masked constant check.
        TraitCheck::VAL_BM *pbm = new TraitCheck::VAL_BM();
        pbm->mask = mask;
        pbm->width = mask_width;
        pbm->n = si;
        val.n_bm = pbm;
        et = TraitCheck::ET_CONST_BM;
    }
    TraitCheck *tc = TraitCheck::getTraitCheck(pt, et, val);
    assert(tc);
    e.first = tc;
    e.second = v;
    return &e;
}

void TraitAnalysisVisitor::visitSwitchInst(SwitchInst &I) {
    //First decide the origin obj|fid of the switch variable.
    Value *cond_var = I.getCondition();
    std::map<void*, std::set<long>> res;
    int orig = this->traceCondOrigin(cond_var, res);
    if (res.empty()) {
        return;
    }
    //Then construct the TraitCheck instance.
    std::vector<int64_t> *cns = new std::vector<int64_t>();
    for (auto &c : I.cases()) {
        ConstantInt *val = c.getCaseValue();
        int64_t c_val = val->getSExtValue();
        // uint64_t c_val = val->getZExtValue();
        cns->push_back(c_val);
    }
    TraitCheck::VAL val;
    val.cset = cns;
    TraitCheck *tc = TraitCheck::getTraitCheck(TraitCheck::PT_SWITCH, TraitCheck::ET_CONST_SET,
                                               val);
    assert(tc);
    //Add the TC to the obj|fid.
    InstLoc *loc = InstLoc::getLoc(&I, this->ctx);
    assert(loc);
    if (orig == 1) {
        for (auto &e : res) {
            AliasObject *obj = (AliasObject*)e.first;
            for (long fid : e.second) {
                this->currState.addTraitCheck(loc, obj, fid, tc);
            }
        }
    } else if (orig == 2) {
        // Record the TC and the origin return vaue.
        CallInst *ci = (CallInst *)(res.begin()->first);
        assert(dyn_cast<CallInst>(ci));
        this->currState.addTraitCheckRet(loc, ci, tc);
    } else if (orig == 3) {
        // Record the TC and the origin phi node.
        PHINode *pi = (PHINode *)(res.begin()->first);
        assert(dyn_cast<PHINode>(pi));
        this->currState.addTraitCheckPHI(loc, pi, tc);
    }
    return;
}

// Given a Value*, try to decide its origin, like an obj|fid, or a return value.
// Return:
// 0: no origin identified
// 1: obj|fid
// 2: return value
int TraitAnalysisVisitor::traceCondOrigin(Value *v, std::map<void*, std::set<long>> &res) {
    v = InstructionUtils::stripAllCasts(v, false);
    if (!v) {
        return 0;
    }
    // Now track the variable back to decide its origin
    // (e.g., an obj|field, a ret value).
    if (dyn_cast<LoadInst>(v)) {
        Value *ptr = dyn_cast<LoadInst>(v)->getPointerOperand();
        assert(ptr);
        std::set<PointerPointsTo *> *ptos = PointsToUtils::getPointsToObjects(
            this->currState, this->ctx, ptr);
        if (!ptos || ptos->empty()) {
            return 0;
        }
        // Collect the pointed-to obj|fid.
        for (PointerPointsTo *pto : *ptos) {
            if (pto && pto->targetObject) {
                res[pto->targetObject].insert(pto->dstfieldId);
            }
        }
        return 1;
    } else if (dyn_cast<CallInst>(v)) {
        // The variable in the comparison is a return value.
        // TODO: perform the inter-procedure tracking.
        res[v].insert(0);
        return 2;
    } else if (dyn_cast<PHINode>(v)) {
        // A concerete example:
        //
        // 40:  ; preds = %36
        // call void @kfree(i8* noundef nonnull %41) //F
        // br label %42, !dbg !592473
        //
        // 42:  ; preds = %17, %36, %40
        // %43 = phi %union.acpi_object* [ null, %40 ], [ %34, %36 ], [ null, %17 ]
        // %44 = icmp eq %union.acpi_object* %43, null
        // br i1 %44, label %160, label %45    //critical conditional
        //
        // 45:  ; preds = %42
        // U
        res[v].insert(0);
        return 3;
    } else {
        // TODO: the variable may be loaded, and then undergoes
        // some calculation or a GEP, e.g., *p+1<2.
        return 0;
    }
    return 0;
}

}  // namespace DRCHECKER
