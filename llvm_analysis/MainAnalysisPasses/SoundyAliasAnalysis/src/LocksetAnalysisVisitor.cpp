//
// Created by hz on 05/08/21.
//

#include "LocksetAnalysisVisitor.h"

using namespace llvm;

namespace DRCHECKER {

    #define DEBUG_CALL_INST

    VisitorCallback* LocksetAnalysisVisitor::visitCallInst(CallInst &I, Function *currFunc,
                                                           CallContext *oldCtx,
                                                           CallContext *currCtx) {
        std::string funcname = (currFunc->hasName() ? currFunc->getName().str() : "");
#ifdef DEBUG_CALL_INST
        dbgs() << "LocksetAnalysisVisitor::visitCallInst(): " << InstructionUtils::getValueStr(&I) << ", callee: " << funcname 
        << ", is_declaration: " << currFunc->isDeclaration() << "\n"; 
#endif
        if (currFunc->isDeclaration()) {
            //Is it a lock/unlock function?
            if (!LocksetAnalysisVisitor::functionChecker->is_lock_function(currFunc)) {
                return nullptr;
            }
#ifdef DEBUG_CALL_INST
            dbgs() << "LocksetAnalysisVisitor::visitCallInst(): it's a lock/unlock.\n"; 
#endif
            //Ok, decide which one it is, lock or unlock.
            bool is_lock;
            std::set<std::string> pairnames = 
                    LocksetAnalysisVisitor::functionChecker->get_paired_lock_funcs(funcname, &is_lock);
            if (pairnames.empty()) {
                //TODO: is there any lock/unlock function that doesn't have a paired one?
                //If there is, we need to re-model the semantics and re-write
                //the lockset analysis logics.
                return nullptr;
            }
            //Now try to get the lock objects.
            std::vector<long> pargs = LocksetAnalysisVisitor::functionChecker->get_lock_arguments(currFunc);
            //Get the ptos of the lock objects.
            //TODO: what if we have multiple args that point to lock objs? (is it possible?)
            std::set<PointerPointsTo*> *lock_objs = new std::set<PointerPointsTo*>();
            for (long n : pargs) {
                Value *arg = I.getArgOperand(n);
                if (!arg) {
                    continue;
                }
                //NOTE: AliasAnalysis will ensure that inlined GEP operator as an arg will be processed and has its pto records.
                std::set<PointerPointsTo*> *ptos = PointsToUtils::getPointsToObjects(this->currState,this->ctx,arg);
                if (ptos && !ptos->empty()) {
                    lock_objs->insert(ptos->begin(),ptos->end());
                }
            }
            //Record this lock/unlock and create the lock entry info.
            InstLoc *loc = InstLoc::getLoc(&I,this->ctx);
            LockInfo *li = new LockInfo(loc,is_lock,lock_objs,&funcname);
#ifdef DEBUG_CALL_INST
            dbgs() << "LocksetAnalysisVisitor::visitCallInst(): pair func: ";
            for (auto &ps : pairnames) {
                dbgs() << ps << ", ";
            } 
            dbgs() << "current LockInfo: \n";
            li->print(dbgs());
#endif
            if (is_lock) {
                this->currState.locks.push_back(li);
            }else {
                this->currState.unlocks.push_back(li);
                // Try to find out its paired lock entry and record it.
                // NOTE: there might be multiple paired lock sites.
                for (int i = this->currState.locks.size() - 1; i >= 0; --i) {
                    LockInfo *t = this->currState.locks[i];
                    if (pairnames.find(t->fn) == pairnames.end()) {
                        // Not a paired lock according to the func name.
                        continue;
                    }
                    // A heuristic here: it's unlikely that the lock/unlock are in different same-level callees,
                    // e.g., A() calls B() and B() puts the lock(), then A() calls C() and C() performs unlock()...
                    // That's to say, the lock's calling context should prefix that of the unlock.
                    // TODO: inspect whether there are exceptions to this heuristic.
                    if (t->loc->isCtxPrefix(loc) < 0) {
                        continue;
                    }
                    // The paired lock/unlock must operate on the same lock object.
                    if (!li->sameLockObjs(t)) {
                        continue;
                    }
                    // Ok, the last check is whether the unlock site is reachable from the lock site, basically
                    // there are three situations:
                    //(1) There is a path from the lock to the unlock, w/o any unlocks in between, suggesting that
                    // the unlock is the counterpart of the lock.
                    //(2) The unlock is reachable from lock in CFG, but every path is blocked by another unlock,
                    // which means that lock is already well paired with other unlocks, and current unlock should be paired
                    // with a different lock instead.
                    //(3) Unreachable in the CFG (obviously not a pair).
                    // Since our static analysis follows the topological order, "unlocks in between" in (1) and (2)
                    // should have already been visited and recorded in t->pairs.
                    std::set<InstLoc *> blockers;
                    for (LockInfo *pt : t->pairs) {
                        if (pt && pt->loc) {
                            blockers.insert(pt->loc);
                        }
                    }
                    if (!loc->reachable(t->loc, &blockers)) {
                        continue;
                    }
                    // Set the pair relationship..
                    li->pairs.insert(t);
                    t->pairs.insert(li);
                }
#ifdef DEBUG_CALL_INST
                dbgs() << "LocksetAnalysisVisitor::visitCallInst(): Located Paired Lock Entry: ";
                for (LockInfo *p : li->pairs) {
                    dbgs() << (const void*)p << ", ";
                }
                dbgs() << "\n";
#endif
            }
#ifdef DEBUG_CALL_INST
            dbgs() << "LocksetAnalysisVisitor::visitCallInst(): #lock: " << this->currState.locks.size() 
            << ", #unlock: " << this->currState.unlocks.size() << "\n";
#endif
            return nullptr;
        }
        //TODO:
        //if the function has a body (i.e., it's not a general kernel function like mutex_lock()), we might also
        //try to model it if we have domain knowledges (e.g., we know it's a customized lock/unlock function).
        //
        //
        // In the end create a new LocksetAnalysisVisitor for the callee.
        LocksetAnalysisVisitor *vis = new LocksetAnalysisVisitor(currState, currFunc, currCtx);
        return vis;
    }

}// namespace DRCHECKER
