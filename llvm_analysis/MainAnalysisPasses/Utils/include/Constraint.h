#ifndef PROJECT_CONSTRAINT_H
#define PROJECT_CONSTRAINT_H

#include "CFGUtils.h"
#include "z3++.h"
#include <optional>
#include <memory>

using namespace z3;

namespace DRCHECKER {

    //One context for all z3 solving tasks across the analysis.
    extern context z3c;

    //Given a pointer to anything (Value*, InstLocTr*, etc.), return
    //a unique z3 variable representing it.
    extern expr get_z3v_expr_bv(void *p);

    //Just return a trivial z3 variable.
    extern expr get_z3v();

    extern expr get_z3v_expr_int(void *p);

    extern void print_z3_expr(raw_ostream &OS, expr &e, bool lbreak = true);

    // This class abstracts the path constraints posed to a certain variable, within one function. 
    // TODO: use std::shared_ptr to replace expr*, or avoid expr* altogether, or
    // consider to use expr_vector.
    class Constraint {
    public:

        Value *v = nullptr;
        std::map<BasicBlock*, std::optional<expr>> cons;

        //Sometimes the constraint is only on an edge, e.g.,
        // if (a) do_sth; return;
        //while in the "do_sth" BB we have the constraint "a != 0", the "a == 0" constraint
        //only exists on the edge from the "br" to "return" BB, but not the "return" BB.
        //We record such edge constraints because they can be useful when we analyze the
        //constraints of a value resulted from a phi node, which conditionally merges values
        //from different edges.
        std::map<BasicBlock*, std::map<BasicBlock*, std::optional<expr>>> cons_edge;

        //All BBs in which the value constraints are unsatisfiable.
        std::set<BasicBlock*> deadBBs;

        //Records which Constraints have been merged into this. 
        std::set<Constraint*> merged;

        Constraint(Value *v) {
            this->v = v;
        }

        ~Constraint() {
            //
        }

        bool satisfiable(expr &e) {
            solver s(z3c);
            s.add(e);
            //"sat", "unsat" or "unknown"
            bool is_sat = false;
            switch (s.check()) {
            case unsat: 
                break;
            default: 
                is_sat = true;
                break;
            }
            //Z3_finalize_memory();
            return is_sat;
        }

        bool hasConstraint(BasicBlock *bb) {
            return (bb && this->cons.find(bb) != this->cons.end() &&
                    this->cons[bb]);
        }

        std::optional<expr> getConstraint(BasicBlock *bb) {
            return this->hasConstraint(bb) ? this->cons[bb] : std::nullopt;
        }

        //Add a new constraint for the value in a certain BB.
        //"solve": if there are already constraints present for the "bb" before this invocation,
        //we will always test the feasibility of the latest combined constraints (after we
        //insert "con"), otherwise if "con" is the very first constraint we have for the "bb",
        //we only test its feasibility if "solve" is true, this can save some solver time for
        //those constraints that we believe must be satisfiable.
        bool addConstraint(expr &con, BasicBlock *bb, bool solve = true) {
            if (!bb) {
                return true;
            }
            if (this->deadBBs.find(bb) != this->deadBBs.end()) {
                //Already dead..
                return false;
            }
            if (this->cons.find(bb) == this->cons.end() || !this->cons[bb]) {
                this->cons[bb] = con;
            }else {
                //Combine the constraints w/ "and".
                this->cons[bb] = *this->cons[bb] && con;
                //There are existing constraints, must solve the combined constraint.
                solve = true;
            }
            if (solve) {
                if (!this->satisfiable(*this->cons[bb])) {
                    // Simplify the constraint to "false".
                    this->cons[bb] = z3c.bool_val(false);
                    this->deadBBs.insert(bb);
                    return false;
                }
            }
            return true;
        }

        //Add a new constraint for the value on the edge from "b0" to "b1",
        //then returns true upon success, false otherwise.
        bool addEdgeConstraint(expr &con, BasicBlock *b0, BasicBlock *b1) {
            if (!b0 || !b1) {
                return false;
            }
            //TODO: verifies that b1 is a successor of b0.
            if (this->deadBBs.find(b0) != this->deadBBs.end() ||
                this->deadBBs.find(b1) != this->deadBBs.end()) {
                //Already dead..
                return false;
            }
            if (this->cons_edge.find(b0) == this->cons_edge.end() ||
                this->cons_edge[b0].find(b1) == this->cons_edge[b0].end() ||
                !this->cons_edge[b0][b1]) {
                this->cons_edge[b0][b1] = con;
            } else {
                //This should be impossible..
                this->cons_edge[b0][b1] = *this->cons_edge[b0][b1] && con;
            }
            return true;
        }

        bool hasEdgeConstraint(BasicBlock *b0, BasicBlock *b1) {
            return (b0 && b1 &&
                    this->cons_edge.find(b0) != this->cons_edge.end() &&
                    this->cons_edge[b0].find(b1) != this->cons_edge[b0].end() &&
                    this->cons_edge[b0][b1]);
        }

        std::optional<expr> getEdgeConstraint(BasicBlock *b0, BasicBlock *b1) {
            return this->hasEdgeConstraint(b0,b1) ? this->cons_edge[b0][b1] : std::nullopt;
        }

        //Add the constraint to all basic blocks in the host function.
        void addConstraint2AllBBs(expr &con, Function *func, bool solve = true) {
            if (!func) {
                return;
            }
            for (BasicBlock &bb : *func) {
                this->addConstraint(con,&bb,solve);
            }
            return;
        }

        //Add the constraint to some specified basic blocks in the host function.
        void addConstraint2BBs(expr &con, std::set<BasicBlock*> &bbs, bool solve = true) {
            if (bbs.empty()) {
                return;
            }
#ifdef TIMING
            auto t0 = InstructionUtils::getCurTime();
#endif
            for (BasicBlock *bb : bbs) {
                this->addConstraint(con,bb,solve);
            }
#ifdef TIMING
            dbgs() << "[TIMING] addConstraint2BBs: ";
            InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
            return;
        }

        //Merge the constraints from another "Constraint" instance for the same
        //llvm Value, basically we AND all the individual constraints.
        void merge(Constraint *c) {
            if (!c || c->v != this->v) {
                return;
            }
            if (this->merged.find(c) != this->merged.end()) {
                //Already merged.
                return;
            }
            //Note that our current z3 expr generation mechanism ensures that
            //as long as the llvm "value" of two "Constraint" instances are the
            //same, their z3 expr will also be compatiable.
            //First do the BB constraints.
            for (auto &e : c->cons) {
                BasicBlock *bb = e.first;
                if (!bb || !e.second) {
                    continue;
                }
                //We specify that "solve" is false here, because "c" should 
                //be the ctx-free Constraint, if its BB constraint has already
                //been evaluated to false, we should already have the dead BB
                //list updated (ctx-free), otherwise it's either evaluated to
                //true or we thought it must be true, in all cases, since "this"
                //doesn't have constarints for this BB, we don't need to evaluate
                //the constraint again.
                this->addConstraint(*e.second,bb,false);
            }
            //Then the edge constraints.
            for (auto &e0 : c->cons_edge) {
                BasicBlock *bb0 = e0.first;
                if (!bb0) {
                    continue;
                }
                for (auto &e1 : e0.second) {
                    BasicBlock *bb1 = e1.first;
                    if (!bb1 || !e1.second) {
                        continue;
                    }
                    //Merge the edge constraints.
                    this->addEdgeConstraint(*e1.second,bb0,bb1);
                }
            }
            this->merged.insert(c);
            return;
        }

        //Return an expr that is true when "zv" is equal to any value in "vs".
        expr getEqvExpr(std::set<int64_t> &vs) {
            expr ev = get_z3v_expr_bv((void*)this->v);
            expr e(z3c);
            bool first = true;
            for (int64_t i : vs) {
                expr t = (ev == z3c.bv_val(i, 64));
                if (first) {
                    e = t;
                    first = false;
                }else {
                    e = (e || t);
                }
            }
            return e;
        }

        //Return an expr that is true when "zv" is not equal to any value in "vs".
        expr getNeqvExpr(std::set<int64_t> &vs) {
            expr ev = get_z3v_expr_bv((void*)this->v);
            expr e(z3c);
            bool first = true;
            for (int64_t i : vs) {
                expr t = (ev != z3c.bv_val(i, 64));
                if (first) {
                    e = t;
                    first = false;
                }else {
                    e = (e && t);
                }
            }
            return e;
        }

        //This is a more general function, given an cmp operator (e.g., >, <) and a signed/unsigned integer,
        //return the expr for "zv" accordingly (zv > C).
        expr getExpr(CmpInst::Predicate pred, int64_t sc, uint64_t uc) {
            expr ev = get_z3v_expr_bv((void*)this->v);
            expr e(z3c);
            switch (pred) {
                case CmpInst::Predicate::ICMP_EQ:
                    return ev == z3c.bv_val(sc, 64);
                case CmpInst::Predicate::ICMP_NE:
                    return ev != z3c.bv_val(sc, 64);
                case CmpInst::Predicate::ICMP_UGT:
                    return ugt(ev, z3c.bv_val(uc, 64));
                case CmpInst::Predicate::ICMP_UGE:
                    return uge(ev, z3c.bv_val(uc, 64));
                case CmpInst::Predicate::ICMP_ULT:
                    return ult(ev, z3c.bv_val(uc, 64));
                case CmpInst::Predicate::ICMP_ULE:
                    return ule(ev, z3c.bv_val(uc, 64));
                case CmpInst::Predicate::ICMP_SGT:
                    return ev > z3c.bv_val(sc, 64);
                case CmpInst::Predicate::ICMP_SGE:
                    return ev >= z3c.bv_val(sc, 64);
                case CmpInst::Predicate::ICMP_SLT:
                    return ev < z3c.bv_val(sc, 64);
                case CmpInst::Predicate::ICMP_SLE:
                    return ev <= z3c.bv_val(sc, 64);
                default:
                    break;
            }
            // Default
            return z3c.bool_val(true);
        }

    private:
        //
    };

    //The solver for the inequality system representing the partial order constraints.
    class POConstraint {
    public:
        POConstraint() {
            this->evec = new expr_vector(z3c);
        }

        ~POConstraint() {
            delete this->evec;
        }

    private:
        expr_vector *evec = nullptr;

        POConstraint(POConstraint *other) {
            assert(other);
            //But each has its own expr vector.
            this->evec = new expr_vector(z3c);
            for (expr e : *(other->evec)) {
                this->evec->push_back(e);
            }
        }

    public:
        POConstraint *fork() {
            return new POConstraint(this);
        }

        //Add a partial-order constraint: i0 should happen before i1.
        //"void*" can be any instruction location class.
        int addConstraint(void *i0, void *i1) {
            if (!i0 || !i1) {
                return 0;
            }
            if (i0 == i1) {
                //This can happen if one inst has multiple lables (e.g., boath a fetch and use),
                //in this case, we assume these two events can satisfy any order constraints.
                return 0;
            }
            expr zv0 = get_z3v_expr_int(i0);
            expr zv1 = get_z3v_expr_int(i1);
            this->evec->push_back(zv0 < zv1);
            return 0;
        }

        //Add a set of partial-order constraints that are connected with OR (||),
        //more specfically: locs[0] < locs[1] || locs[2] < locs[3] || ...
        int addConstraintOr(std::vector<void*> &locs) {
            //Sanity checks first.
            if (locs.size() < 4 || locs.size() % 2) {
                return -1;
            }
            std::vector<void*> flt_locs;
            for (unsigned i = 0; i + 1 < locs.size(); i += 2) {
                if (!locs[i] || !locs[i+1]) {
                    continue;
                }
                if (locs[i] == locs[i+1]) {
                    //This can happen if one InstLocTr has multiple lables (e.g., boath a
                    //fetch and use), in this case, we assume these two events can satisfy
                    //any order constraints.
                    continue;
                }
                flt_locs.push_back(locs[i]);
                flt_locs.push_back(locs[i+1]);
            }
            if (flt_locs.empty()) {
                return -1;
            }
            //Construct the OR expression connecting each individual expr.
            expr e(z3c);
            bool first = true;
            for (unsigned i = 0; i + 1 < flt_locs.size(); i += 2) {
                expr zv0 = get_z3v_expr_int(flt_locs[i]);
                expr zv1 = get_z3v_expr_int(flt_locs[i+1]);
                if (first) {
                    e = (zv0 < zv1);
                    first = false;
                } else {
                    e = (e || (zv0 < zv1));
                }
            }
            //Add to the solver.
            this->evec->push_back(e);
            return 0;
        }

        //Reset the PO constraints.
        void reset() {
            while(!this->evec->empty()) {
                this->evec->pop_back();
            }
        }

        //Try to solve the partial-order constraint system, and provide a solution (in the
        //form of a valid InstLoc sequence) if present, otherwise return false.
        bool solve(std::vector<void*> *seq = nullptr) {
            solver z3s(z3c);
            for (expr e : *(this->evec)) {
                z3s.add(e);
            }
            //"sat", "unsat" or "unknown"
            switch (z3s.check()) {
            case unsat:
                return false;
            case sat: {
                //Get a concerete solution and translate it to an InstLoc sequence.
                std::vector<std::pair<void*, int>> lst;
                model m = z3s.get_model();
                for (unsigned i = 0; i < m.size(); i++) {
                    func_decl v = m[i];
                    // this problem contains only constants
                    assert(v.arity() == 0);
                    long pv = std::stol(v.name().str());
                    lst.push_back(std::make_pair((void*)pv, m.get_const_interp(v)));
                }
                std::sort(lst.begin(),lst.end(),
                    [](auto const& z0, auto const& z1) -> bool {
                        return (z0.second < z1.second);
                    }
                );
                if (seq) {
                    seq->clear();
                    for (unsigned i = 0; i < lst.size(); ++i) {
                        seq->push_back(lst[i].first);
                    }
                }
                return true;
            }
            default:
                //Not sure whether it's solvable, to be conservative we assume it is.
                //TODO: why could this happen?
                return true;
            }
            return true;
        }
    };

} //namespace

#endif //PROJECT_CONSTRAINT_H
