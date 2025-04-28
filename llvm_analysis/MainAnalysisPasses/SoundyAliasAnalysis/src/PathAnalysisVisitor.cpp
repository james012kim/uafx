//
// Created by hz on 8/13/20.
//

#include "PathAnalysisVisitor.h"

using namespace llvm;

namespace DRCHECKER {

    #define DEBUG_VISIT_SWITCH_INST
    #define DEBUG_VISIT_BRANCH_INST
    #define DEBUG_CALL_INST
    #define DEBUG_VISIT_PHI_INST

    void PathAnalysisVisitor::_visitSwitchInst(SwitchInst &I) {
#ifdef DEBUG_VISIT_SWITCH_INST
        dbgs() << "PathAnalysisVisitor::visitSwitchInst(): " << InstructionUtils::getValueStr(&I) << "\n";
#endif
        Value *cond_var = I.getCondition();
        //Two tasks here:
        //(1) calculate the context-insensitive constraints of "cond_var" (e.g., apply in all
        //calling contexts), if not before.
        //(2) take the context-sensitive constraints of "cond_var" into account (e.g., "cond_var"
        //might be an argument provided by the caller) and calculate the context-dependent
        //dead BBs.
        if (!cond_var) {
            return;
        }
        Constraint *c0 = this->currState.getConstraints(nullptr, cond_var, false);
        if (!c0) {
            //This means we haven't finished task (1) for "cond_var" yet, do it now.
            c0 = this->_visitSwitchInst_ctx_free(I);
            assert(c0);
            //Update the dead BB list if any, these are dead regardless of the
            //calling contexts.
            this->currState.updateDeadBBs(nullptr, c0->deadBBs);
        }
        //Now task (2).
        Constraint *c1 = this->currState.getConstraints(this->ctx, cond_var, false);
        if (!c1) {
            //There are no context-specific constraints, we're done.
            return;
        }
        //Combine the constraints from the 2 source, solve and update the
        //ctx-specific dead BB list.
        c1->merge(c0);
        this->currState.updateDeadBBs(this->ctx, c1->deadBBs);
        return;
    }
    
    void PathAnalysisVisitor::visitSwitchInst(SwitchInst &I) {
#ifdef TIMING
        auto t0 = InstructionUtils::getCurTime();
#endif
        this->_visitSwitchInst(I);
#ifdef TIMING
        dbgs() << "[TIMING] PathAnalysisVisitor::visitSwitchInst(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
        return;
    }

    Constraint *PathAnalysisVisitor::_visitSwitchInst_ctx_free(SwitchInst &I) {
        Value *cond_var = I.getCondition();
        BasicBlock *def_bb = I.getDefaultDest();
        unsigned num = I.getNumCases();
#ifdef DEBUG_VISIT_SWITCH_INST
        dbgs() << "PathAnalysisVisitor::_visitSwitchInst_ctx_free(): Cond Var: "
        << InstructionUtils::getValueStr(cond_var) << " #cases: " << num << "\n";
#endif
        //Collect the cases and values of this switch.
        //case bb -> the switch value(s) to it.
        std::map<BasicBlock*,std::set<int64_t>> caseMap;
        std::set<int64_t> cns;
        for (auto c : I.cases()) {
            ConstantInt *val = c.getCaseValue();
            int64_t c_val = val->getSExtValue();
            //uint64_t c_val = val->getZExtValue();
            cns.insert(c_val);
            BasicBlock *bb = c.getCaseSuccessor();
#ifdef DEBUG_VISIT_SWITCH_INST
            dbgs() << "Case Value: " << c_val << " Dst BB: " << InstructionUtils::getBBStrID(bb)
            << "\n";
#endif
            if (!val || !bb) {
                continue;
            }
            caseMap[bb].insert(c_val);
        }
        //Now add context-insensitive constraints for each branch of this switch for "cond_var",
        //note that here we assume that "I" hasn't been visited before and we don't need to test
        //the feasibility of the ctx-insensitive switch branch constraints - they must be
        //satisfiable (e.g., just things like "c == N" or "c != N0 && c != N1").
        Constraint *c = this->currState.getConstraints(nullptr, cond_var, true);
        assert(c);
        std::map<BasicBlock*, std::set<BasicBlock *>> *cMap = 
                            BBTraversalHelper::getCondCoverMap(I.getParent());
        for (auto &e : caseMap) {
            BasicBlock *bb = e.first;
            //We need to ensure that "bb" is constrained by the switch bb.
            if (cMap && cMap->find(bb) != cMap->end()) {
                std::set<int64_t> cvs, *pcvs = &e.second;
                if ((*cMap)[bb].size() > 1) {
                    for (BasicBlock *succ : (*cMap)[bb]) {
                        if (!succ || caseMap.find(succ) == caseMap.end()) {
                            dbgs() << "!!! PathAnalysisVisitor::_visitSwitchInst_ctx_free(): "
                            << "succ in cover map lost in caseMap: "
                            << InstructionUtils::getBBStrID(succ) << "\n";
                            continue;
                        }
                        cvs.insert(caseMap[succ].begin(),caseMap[succ].end());
                    }
                    pcvs = &cvs;
                }
                // Get all BBs dominated by "bb", these are BBs belonging only to the current case branch.
                std::set<BasicBlock *> dombbs;
                BBTraversalHelper::getDominatees(bb, dombbs);
                // Update the constraints.
                expr cons = c->getEqvExpr(*pcvs);
                c->addConstraint2BBs(cons, dombbs, false);
            } else {
                expr cons = c->getEqvExpr(e.second);
                c->addEdgeConstraint(cons, I.getParent(), bb);
            }
        }
        //Deal with the default case.
        if (def_bb) {
            if (cMap && cMap->find(def_bb) != cMap->end()) {
                if ((*cMap)[def_bb].size() > 1) {
                    //This means there are other normal case BBs that can also
                    //reach this default case handler, so we need to exclude
                    //these case numbers from "cns".
                    for (BasicBlock *succ : (*cMap)[def_bb]) {
                        if (!succ || succ == def_bb) {
                            continue;
                        }
                        if (caseMap.find(succ) == caseMap.end()) {
                            dbgs() << "!!! PathAnalysisVisitor::_visitSwitchInst_ctx_free(): "
                            << "succ in cover map lost in caseMap: "
                            << InstructionUtils::getBBStrID(succ) << "\n";
                            continue;
                        }
                        //Delete case value from "cns".
                        for (auto c : caseMap[succ]) {
                            cns.erase(c);
                        }
                    }
                }
                std::set<BasicBlock *> dombbs;
                BBTraversalHelper::getDominatees(def_bb, dombbs);
                expr e = c->getNeqvExpr(cns);
                c->addConstraint2BBs(e, dombbs, false);
            } else {
                // Add edge constraints instead.
                expr e = c->getNeqvExpr(cns);
                c->addEdgeConstraint(e, I.getParent(), def_bb);
            }
        }
        return c;
    }

    VisitorCallback* PathAnalysisVisitor::_visitCallInst(CallInst &I, Function *currFunc,
                                                        CallContext *oldCtx,
                                                        CallContext *currCtx) {
#ifdef DEBUG_CALL_INST
        dbgs() << "PathAnalysisVisitor::visitCallInst(): " << InstructionUtils::getValueStr(&I)
        << ", callee: " << currFunc->getName().str() << "\n";
#endif
        // if this is a kernel internal function, just skip it for now.
        if(currFunc->isDeclaration()) {
            //this->handleKernelInternalFunction(I, currFunc);
            return nullptr;
        }
        // Ok, we need to propagate the constraints from the actual args to the formal args, if any.
        int arg_no = -1;
        for (Value *arg : I.args()) {
            ++arg_no;
            //Get the formal argument.
            Argument *farg = InstructionUtils::getArg(currFunc,arg_no);
            if (!arg || !farg) {
                continue;
            }
            Constraint *nc = nullptr;
            if (!dyn_cast<Constant>(arg)) {
                //The actual argument is a variable, see whether it has any constraints
                //at current point.
                Value *varg = arg;
                Constraint *cons = this->currState.getAvailableConstraints(this->ctx, arg);
                if (!cons) {
                    //Try to strip the pointer casts and obtain the constraints again.
                    //TODO: maybe in the path analysis we also need to process the cast IRs.
                    varg = arg->stripPointerCasts();
                    if (varg != arg) {
                        cons = this->currState.getAvailableConstraints(this->ctx, varg);
                    }
                }
                if (!cons || !I.getParent() || !cons->hasConstraint(I.getParent())) {
                    // No constraints for current actual arg, or no constraints in current BB.
                    continue;
                }
                expr &e = *cons->cons[I.getParent()];
#ifdef DEBUG_CALL_INST
                dbgs() << "PathAnalysisVisitor::visitCallInst(): propagate constraint for arg "
                << arg_no << ": " << InstructionUtils::getValueStr(arg) << " -> "
                << InstructionUtils::getValueStr(farg) << ", constraint: " << e.to_string() << "\n";
#endif
                nc = new Constraint(farg);
                expr ne = (e && (get_z3v_expr_bv((void*)farg) == get_z3v_expr_bv((void*)varg)));
                //The constraint of the variable must be satisfiable, otherwise this
                //call site will be unreachable (in a dead BB).
                nc->addConstraint2AllBBs(ne, currFunc, false);
            } else {
                //The actual argument is a constant, so we need to add a constraint to the formal arg.                
                int64_t c_val_i;
                uint64_t c_val_u;
                if (InstructionUtils::getConstantValue(dyn_cast<Constant>(arg),&c_val_i,&c_val_u)) {
                    std::set<int64_t> vs{c_val_i};
                    nc = new Constraint(farg);
                    expr e = nc->getEqvExpr(vs);
#ifdef DEBUG_CALL_INST
                    dbgs() << "PathAnalysisVisitor::visitCallInst(): actual arg " << arg_no
                           << " is a constant int: " << c_val_i << ", so add the constraint " << e.to_string()
                           << " to the formal arg: " << InstructionUtils::getValueStr(farg) << "\n";
#endif
                    // This is simply a eqv constant constraint that must be satisfiable
                    // for the unanalyzed callee.
                    nc->addConstraint2AllBBs(e, currFunc, false);
                }
            }
            //Add the formal arg constraint to the global state,
            //this is the context-sensitive one.
            this->currState.setConstraints(currCtx,farg,nc);
        }
        // In the end create a new PathAnalysisVisitor for the callee.
        PathAnalysisVisitor *vis = new PathAnalysisVisitor(currState, currFunc, currCtx);
        return vis;
    }

    VisitorCallback* PathAnalysisVisitor::visitCallInst(CallInst &I, Function *currFunc,
                                                        CallContext *oldCtx,
                                                        CallContext *currCtx) {
#ifdef TIMING
        auto t0 = InstructionUtils::getCurTime();
#endif
        VisitorCallback *vis = this->_visitCallInst(I, currFunc, oldCtx, currCtx);
#ifdef TIMING
        dbgs() << "[TIMING] PathAnalysisVisitor::visitCallInst(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
        return vis;
    }

    void PathAnalysisVisitor::_visitBranchInst(BranchInst &I) {
        if (!I.isConditional()) {
            return;
        }
        Value *cond = I.getCondition();
        if (!cond) {
            return;
        }
        //Similar as in visitSwitchInst(), again we have two tasks here:
        //(1) calculate the ctx-free constraints and dead BBs of "cond", if not done yet;
        //(2) combine the ctx-specific constraints.
        Constraint *c0 = nullptr;
        if (this->currState.brConstraints.find(&I) != this->currState.brConstraints.end()) {
            //We have processed this branch inst before for the ctx-free constraints.
            c0 = this->currState.brConstraints[&I];
            if (!c0) {
                //Likely this is not a br inst in our scope, skip.
                return;
            }
        } else {
            //A new br inst, analyze its ctx-free constraints.
            c0 = this->_visitBranchInst_ctx_free(I);
        }
        if (!c0) {
            //We don't support analyzing this br inst (e.g., maybe it has a complex
            //cmp pattern).
            return;
        }
        //Update the ctx-free dead BBs.
        this->currState.updateDeadBBs(nullptr, c0->deadBBs);
        //Now do the task (2).
        Constraint *c1 = this->currState.getConstraints(this->ctx, c0->v, false);
        if (!c1) {
            //There are no context-specific constraints, we're done.
            return;
        }
        //Combine the constraints from the 2 source, solve and update the
        //ctx-specific dead BB list.
        c1->merge(c0);
        this->currState.updateDeadBBs(this->ctx, c1->deadBBs);
        return;
    }
    
    //We collect and solve simple conditionals in the form of "V op C", where V is a variable and C constant, op is simple
    //binary operators (e.g., ==, <, >, <=, >=).
    void PathAnalysisVisitor::visitBranchInst(BranchInst &I) {
#ifdef TIMING
        auto t0 = InstructionUtils::getCurTime();
#endif
        this->_visitBranchInst(I);
#ifdef TIMING
        dbgs() << "[TIMING] PathAnalysisVisitor::visitBranchInst(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
        return;
    }

    Constraint *PathAnalysisVisitor::_visitBranchInst_ctx_free(BranchInst &I) {
        Value *cond = I.getCondition();
        if (!cond) {
            return nullptr;
        }
        //Marked this branch inst as processed.
        this->currState.brConstraints[&I] = nullptr;
        //First see whether this "br" is a simple comparison of the form we consider.
        CmpInst *ci = dyn_cast<CmpInst>(cond);
        Value *v = nullptr;
        int64_t sc = 0;
        uint64_t uc = 0;
        CmpInst::Predicate pred, rpred;
        if (ci) {
            //Ok, see whether it's the desired form (i.e., variable vs. constant).
            Value *op0 = ci->getOperand(0);
            Value *op1 = ci->getOperand(1);
            if (!op0 || !op1) {
                return nullptr;
            }
            if (dyn_cast<Constant>(op0) || dyn_cast<Constant>(op1)) {
                if (!dyn_cast<Constant>(op0)) {
                    if (!InstructionUtils::getConstantValue(dyn_cast<Constant>(op1),&sc,&uc)) {
                        return nullptr;
                    }
                    v = op0;
                    pred = ci->getPredicate();
                    rpred = ci->getInversePredicate();
                } else if (!dyn_cast<Constant>(op1)) {
                    if (!InstructionUtils::getConstantValue(dyn_cast<Constant>(op0),&sc,&uc)) {
                        return nullptr;
                    }
                    v = op1;
                    pred = ci->getInversePredicate();
                    rpred = ci->getPredicate();
                } else {
                    //Both are constants? Surprising that this is not optimized out by the compiler...
                    //TODO: need to find a way to skip the dead code since we can already evaluate the conditional.
                    return nullptr;
                }
                //Construct the Z3 constraint on the variable "v"...
            } else {
                //Both are variables, ignore.
                return nullptr;
            }
        } else {
            //This means the conditional is about a boolean variable (e.g., if(b)), for which we should pose constraints.
            //NOTE: in LLVM "false" must be numerically 0, but "true" might not be 1, so we use 0 as the baseline.
            v = cond;
            pred = CmpInst::Predicate::ICMP_NE;
            rpred = CmpInst::Predicate::ICMP_EQ;
            sc = uc = 0;
        }
#ifdef DEBUG_VISIT_BRANCH_INST
        dbgs() << "PathAnalysisVisitor::_visitBranchInst_ctx_free(): Processing BR: "
        << InstructionUtils::getValueStr(&I) << ", pred: " << pred << ", v: "
        << InstructionUtils::getValueStr(v) << ", sc: " << sc << ", uc: " << uc << "\n";
#endif
        //Ok, we're ready to construct the z3 expressions now.
        //The constraints here are purely decided by the branch IR itself, thus ctx-free.
        Constraint *c = this->currState.getConstraints(nullptr, v, true);
        assert(c);
        std::map<BasicBlock*, std::set<BasicBlock *>> *cMap = 
                            BBTraversalHelper::getCondCoverMap(I.getParent());
        //Figure out the BBs belonging to each branch..
        BasicBlock *tb = I.getSuccessor(0);
        BasicBlock *fb = I.getSuccessor(1);
        //If there are other paths to the initial branch BB (i.e., bypass the conditional), we will not pose the constraints.
        if (tb && cMap && cMap->find(tb) != cMap->end()) {
            //Get all dominated BBs, these are BBs belonging only to the current branch.
            std::set<BasicBlock*> dombbs;
            BBTraversalHelper::getDominatees(tb, dombbs);
            //Update the constraints.
            expr cons = c->getExpr(pred,sc,uc);
            c->addConstraint2BBs(cons,dombbs,false);
        } else {
            //Pose the edge constraint instead.
            expr cons = c->getExpr(pred,sc,uc);
            c->addEdgeConstraint(cons,I.getParent(),tb);
        }
        //Process the false branch..
        if (fb && cMap && cMap->find(fb) != cMap->end()) {
            //Get all dominated BBs, these are BBs belonging only to the current branch.
            std::set<BasicBlock*> dombbs;
            BBTraversalHelper::getDominatees(fb, dombbs);
            //Update the constraints.
            expr cons = c->getExpr(rpred,sc,uc);
            c->addConstraint2BBs(cons,dombbs,false);
        } else {
            //Pose the edge constraint instead.
            expr cons = c->getExpr(rpred,sc,uc);
            c->addEdgeConstraint(cons,I.getParent(),fb);
        }
        //Update the global map.
        this->currState.brConstraints[&I] = c;
        return c;
    }

    void PathAnalysisVisitor::_visitPHINode(PHINode &I) {
        //Get the value constraint of the final merged value, by considering each
        //source value (and its BB/Edge constraint) in the phi node.
        std::set<int64_t> imms;
        std::map<Value*, expr_vector*> exprs;
#ifdef DEBUG_VISIT_PHI_INST
        dbgs() << "PathAnalysisVisitor::visitPHINode(): Processing PHI: "
        << InstructionUtils::getValueStr(&I) << "\n";
#endif
        int expr_cnt = 0;
        //indicate whether there are any imm numbers in the phi vector.
        bool any_imm = false;
        //if any source variable of the phi has ctx-specific constraints, then
        //the phi also needs the ctx-specific ones, otherwise not. 
        bool any_ctx_var = false;
        for (unsigned i = 0; i < I.getNumIncomingValues(); ++i) {
            Value *v = I.getIncomingValue(i);
            if (!any_imm &&
                dyn_cast<Constant>(v) &&
                InstructionUtils::getConstantValue(dyn_cast<Constant>(v), nullptr, nullptr))
            {
                any_imm = true;
            }
            if (!any_ctx_var &&
                !dyn_cast<Constant>(v) &&
                this->currState.getConstraints(this->ctx, v, false))
            {
                any_ctx_var = true;
            }
        }
        //If there is no need to calculate the ctx-specific constraints and we
        //have already got the ctx-free ones, we're done.
        if (!any_ctx_var &&
            this->currState.getConstraints(nullptr, &I, false))
        {
#ifdef DEBUG_VISIT_PHI_INST
            dbgs() << "PathAnalysisVisitor::visitPHINode(): ctx-free constraints "
            << "already generated before.\n";
#endif
            return;
        }
        if (this->currState.getConstraints(this->ctx, &I, false)) {
            //This means we have visited this phi (within the same ctx) before and 
            //generated a ctx-specific constraint for it, but now we're here again.
            //This can be due to the loop (depends on how many times we need to
            //analyze the loop).
            //Currently we only try the ctx-specific analysis once.
            //TODO: consider better weays to handle loop.
#ifdef DEBUG_VISIT_PHI_INST
            dbgs() << "PathAnalysisVisitor::visitPHINode(): ctx-specific constraints "
            << "already generated before, maybe due to the loop.\n";
#endif
            return; 
        }
        //Otherwise go ahead to calculate the phi constraints.
        bool wild_phi = false;
        std::map<Value*,std::set<unsigned>> merged_expr_ids;
        for (unsigned i = 0; i < I.getNumIncomingValues(); ++i) {
            Value *v = I.getIncomingValue(i);
            BasicBlock *bb = I.getIncomingBlock(i);
            if (!v || !bb) {
                return;
            }
            //Is the value a constant? If so, the constraint is trivial to get.
            if (dyn_cast<Constant>(v)) {
                int64_t sc = 0;
                uint64_t uc = 0;
                if (!InstructionUtils::getConstantValue(dyn_cast<Constant>(v), &sc, &uc)) {
                    //Constant but we cannot parse the value? Hmm...
                    return;
                }
                imms.insert(sc);
            } else {
                // Get the constraint for this value.
                Constraint *c = this->currState.getAvailableConstraints(this->ctx, v);
                if (c) {
                    // First consider the edge constraint, if none, then the BB constraint
                    // posed on the source BB.
                    auto oe = c->getEdgeConstraint(bb, I.getParent());
                    if (!oe) {
                        oe = c->getConstraint(bb);
                    }
                    if (!oe) {
#ifdef DEBUG_VISIT_PHI_INST
                        dbgs() << "PathAnalysisVisitor::visitPHINode(): cannot get the location-bound"
                        << " constraints of: " << InstructionUtils::getValueStr(v) << "\n";
#endif
                        return;
                    }
                    expr &e = *oe;
#ifdef DEBUG_VISIT_PHI_INST
                    //dbgs() << "PathAnalysisVisitor::visitPHINode(): v: "
                    //<< InstructionUtils::getValueStr(v) << ", e: ";
                    //DRCHECKER::print_z3_expr(dbgs(), e, true);
#endif
                    if (exprs.find(v) == exprs.end()) {
                        exprs[v] = new expr_vector(z3c);
                        exprs[v]->push_back(e);
                        merged_expr_ids[v].insert(e.id());
                    } else if (merged_expr_ids[v].find(e.id()) == merged_expr_ids[v].end()) {
                        // This branch is possible because a "phi" can merge the same
                        // top-level llvm var just from different incoming BBs and thus
                        // w/ different constraints, we merge these constraints here.
                        expr pe = exprs[v]->back();
                        exprs[v]->pop_back();
#ifdef DEBUG_VISIT_PHI_INST
                        //dbgs() << "PathAnalysisVisitor::visitPHINode(): exprs[v]: ";
                        //DRCHECKER::print_z3_expr(dbgs(), pe, true);
#endif
                        exprs[v]->push_back((pe || e));
#ifdef DEBUG_VISIT_PHI_INST
                        //expr te1 = exprs[v]->back();
                        //dbgs() << "PathAnalysisVisitor::visitPHINode(): after merge: ";
                        //DRCHECKER::print_z3_expr(dbgs(), te1, true);
#endif
                        merged_expr_ids[v].insert(e.id());
                        merged_expr_ids[v].insert(exprs[v]->back().id());
                    }
#ifdef DEBUG_VISIT_PHI_INST
                    //expr te2 = exprs[v]->back();
                    //dbgs() << "PathAnalysisVisitor::visitPHINode(): out-scope, exprs[v]: ";
                    //DRCHECKER::print_z3_expr(dbgs(), te2, true);
#endif
                } else if (any_imm) {
                    //There is no constraints for this non-constant, but we know that
                    //some incoming values are imms, this indicates that this non-constant
                    //should also take a numeric value, but since it's not constrained,
                    //we can assume that it can take any values - essentially making
                    //this phi node have a "true" constraint expr.
                    //NOTE: we explicitly give such phi nodes a "true" expr instead of
                    //nothing (as for phis merging all non-constant values), since this
                    //can hint the later killer locs identification to continue tracing
                    //each individual incoming value upward.
                    wild_phi = true;
                } else {
                    //TODO: no constraint, not a ptr merge, what to do?
#ifdef DEBUG_VISIT_PHI_INST
                        dbgs() << "PathAnalysisVisitor::visitPHINode(): no constraints for "
                        << InstructionUtils::getValueStr(v) << ", no imms in the phi neither.\n";
#endif
                    return;
                }
                ++expr_cnt;
            }
            if (wild_phi) {
                break;
            }
        }
#ifdef DEBUG_VISIT_PHI_INST
        dbgs() << "PathAnalysisVisitor::visitPHINode(): incoming values: #imm: " << imms.size()
        << ", #expr: " << expr_cnt << "\n";
#endif
        if (imms.empty() && exprs.empty() && !wild_phi) {
            //No constraints to merge.
            return;
        }
        //Get the BBs affected by the phi node constraints, basically all the BBs dominated
        //by the BB which defines the phi node.
        //Note that later some of these BBs may be updated with stricter constraints
        //(e.g., there is a conditional involving the merged value later, generating
        //finer-grained constraint space).
        std::set<BasicBlock*> dombbs;
        BBTraversalHelper::getDominatees(I.getParent(), dombbs);
        //At least the defining BB is in the set.
        assert(!dombbs.empty());
        //Now construct the expr for the merged value, by connecting all the incoming
        //constraints with OR.
        //TODO: to further save time we shouldn't re-generate all the constraints
        //for every ctx-specific "Constraint", but copy the shared parts from the
        //ctx-free "Constraint" and only update the constraints related to ctx-specific
        //variables.
        Constraint *cm = this->currState.getConstraints((any_ctx_var ? this->ctx : nullptr),
                                                        &I, true);
        if (!cm) {
            return;
        }
        expr me = z3c.bool_val(true);
        if (!wild_phi) {
            me = cm->getEqvExpr(imms);
            for (auto &e0 : exprs) {
                Value *v = e0.first;
                expr se = e0.second->back();
                e0.second->pop_back();
#ifdef DEBUG_VISIT_PHI_INST
                dbgs() << "PathAnalysisVisitor::visitPHINode(): se: ";
                DRCHECKER::print_z3_expr(dbgs(), se, true);
#endif
                expr ne = (se && (get_z3v_expr_bv(v) == get_z3v_expr_bv(&I)));
#ifdef DEBUG_VISIT_PHI_INST
                dbgs() << "PathAnalysisVisitor::visitPHINode(): conjuncted ne: ";
                DRCHECKER::print_z3_expr(dbgs(), ne, true);
#endif
                if (me) {
                    me = (me || ne);
                } else {
                    me = ne;
                }
            }
        }
#ifdef DEBUG_VISIT_PHI_INST
        dbgs() << "PathAnalysisVisitor::visitPHINode(): merged z3 expr constraint: "
        << me.to_string() << "\n";
#endif
        //Update the constraints to related BBs.
        //Unlike the conditionals in br or switch, the merged value is *defined*
        //by the phi node in the SSA form, its constraints just OR connect some
        //previous satisfiable individual constraints (otherwise the BB is already
        //dead and we shouldn't have reached this phi) - so we don't need to solve 
        //the constraints of this phi merge.
        cm->addConstraint2BBs(me, dombbs, false);
        return;
    }

    void PathAnalysisVisitor::visitPHINode(PHINode &I) {
#ifdef TIMING
        auto t0 = InstructionUtils::getCurTime();
#endif
        this->_visitPHINode(I);
#ifdef TIMING
        dbgs() << "[TIMING] PathAnalysisVisitor::visitPHINode(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
        return;
    }

    //The main purpose is to propagate the variable constraints across
    //the type conversion (e.g., i32 -> i64).
    void PathAnalysisVisitor::visitCastInst(CastInst &I) {
        //The logic is simple:
        //(1) if the src variable has ctx-specific constraints, the same ones
        //should be generated for the dst variable;
        //(2) if the src has ctx-free constraints and we haven't propagated
        //them to the dst, just do it;
        //Otherwise do nothing.
        Value *sv = I.getOperand(0);
        if (!sv || !I.getParent()) {
            return;
        }
        Constraint *cs0 = this->currState.getConstraints(nullptr, sv, false);
        Constraint *cs1 = this->currState.getConstraints(this->ctx, sv, false);
        if (!cs0 && !cs1) {
            //No constraints for the source value.
            return;
        }
        //Before proceeding, also make sure that we haven't visited this cast
        //under the same ctx previously (loop).
        Constraint *cd1 = this->currState.getConstraints(this->ctx, &I, false);
        if (cd1) {
            //Already visited..
            return;
        }
        //Now propagate the constraints from src to dst..
        std::set<BasicBlock*> bbs;
        if (cs1) {
            cd1 = this->currState.getConstraints(this->ctx, &I, true);
            this->_propConstraints4Cast(I, cs1, cd1);
        } else {
            //Only the ctx-free constraints are available, generate
            //it for the dst value if we haven't.
            Constraint *cd0 = this->currState.getConstraints(nullptr, &I, false);
            if (cd0) {
                //Already generated the ctx-free constraints for the dst value.
                return;
            }
            cd0 = this->currState.getConstraints(nullptr, &I, true);
            this->_propConstraints4Cast(I, cs0, cd0);
        }
        return;
    }

    //Propagate the constraints from "cs" to "cd".
    void PathAnalysisVisitor::_propConstraints4Cast(CastInst &I, Constraint *cs, Constraint *cd) {
        if (!I.getParent() || !cs || !cd) {
            return;
        }
        BasicBlock *bb = I.getParent();
        // Get the constraints of the src value at the current BB.
        if (!bb || !cs->hasConstraint(bb)) {
            return;
        }
        expr &e = *cs->cons[bb];
        // Get the affected BBs of this cast.
        std::set<BasicBlock*> bbs;
        BBTraversalHelper::getDominatees(bb, bbs);
        expr de = (e && get_z3v_expr_bv(cs->v) == get_z3v_expr_bv(&I));
        // The constraints should've solved for the src value, no need
        // to solve it again for the dst.
        cd->addConstraint2BBs(de, bbs, false);
        return;
    }

}// namespace DRCHECKER