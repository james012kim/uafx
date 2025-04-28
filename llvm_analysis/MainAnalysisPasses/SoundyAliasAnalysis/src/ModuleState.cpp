#include "ModuleState.h"

namespace DRCHECKER {

    #define MAX_SUPP_LOC_ADD_ITERATION 3
    #define MAX_SUPP_LOC_ADD_NUM 32
    
    //Add one pto path "seq" for "locTr".
    int ThreadSched::addOnePtoPath(std::shared_ptr<InstLocTr> locTr,
                                   std::vector<InstLoc*> &seq) {
        if (!locTr || seq.empty()) {
            return 0;
        }
        //Ensure that the passed-in "locTr" is within this sched.
        Thread *tr = locTr->getTr(this);
        if (std::find(this->trs.begin(), this->trs.end(), tr) == this->trs.end()) {
            return 0;
        }
        //Insert the pto path, things to note:
        //(1) Every path node of a pto path must be inserted prior to "locTr"
        //within the same thread, otherwise, the warning can be invalid since
        //the desired pto record cannot be established.
        //TODO
        return 0;
    }

    //Add the path nodes that enable the required pto at the F/U sites
    //(e.g., make the "p" in free(p) point to the desired "fobj" but not others).
    //Return 0 for success, negative values if we can early decide that it's a FP.
    int ThreadSched::addPtoPaths(AliasObject *fobj, AliasObject *uobj) {
        if (fobj && this->locTr0) {
            //Get the pto path leading to "fobj" at the F site.
            std::set<PointerPointsTo*> *ptos = fobj->getFreePtos(this->locTr0->loc);
            //IF there are multiple pto records to the same object, there can be
            //multiple pto paths, to be conservative (e.g., avoid FN), we will not
            //add the pto path constraints then.
            if (ptos && ptos->size() == 1 && *(ptos->begin())) {
                PointerPointsTo *pto = *(ptos->begin());
                int r = this->addOnePtoPath(this->locTr0, pto->propagatingHistory);
                if (r < 0) {
                    return r;
                }
            }
        }
        if (uobj && this->locTr1) {
            //Get the pto path leading to "uobj" at the U site.
            std::set<PointerPointsTo*> ptos;
            uobj->getUsePtos(this->locTr1->loc, ptos);
            //Same reasoning as above.
            if (ptos.size() == 1 && *(ptos.begin())) {
                PointerPointsTo *pto = *(ptos.begin());
                int r = this->addOnePtoPath(this->locTr1, pto->propagatingHistory);
                if (r < 0) {
                    return r;
                }
            }
        }
        return 0;
    }
    
    // Add escape/fetch path nodes and related constraints to the thread schedule to trigger the UAF.
    // Return: 0 for success, -1 if we think the validation process should be early terminated
    //(e.g., the UAF is not possible to trigger).
    int ThreadSched::addEFPaths(EqvObjPair *ep0, EqvObjPair *ep1) {
        assert(ep1 && this->locTr0 && this->locTr1);
        std::shared_ptr<InstLocTr> flocTr = this->locTr0;
        std::shared_ptr<InstLocTr> ulocTr = this->locTr1;
        // The general rule is to make the control flow as simple as possible
        // Get the F/U objects.
        AliasObject *fobj = (ep0 ? ep0->dst : ep1->src);
        AliasObject *uobj = ep1->dst;
        if (fobj == uobj) {
            // The F/U objs are the same, so no need to consider the escape/fetch paths.
            return 0;
        }
        // Now assign the escape/fetch path nodes to the threads and encode related constraints.
        if (ep0) {
            // The flow is that first a concerete obj0 escape/fetch (ep0) to a dummy obj1 that is freed,
            // then the same obj0 escape/fetch (ep1) to a dummy obj2 that is used.
            //(1) first consider the data flow in ep0.
            if (this->addOneEFPath(ep0, flocTr) < 0) {
                return -1;
            }
            //(2) then consider the data flow in ep1.
            if (this->addOneEFPath(ep1, ulocTr) < 0) {
                return -1;
            }
        } else {
            // The flow here is that the freed obj e/f to the use site, so only need to consider
            // ep1 with the use site as the end point.
            if (this->addOneEFPath(ep1, ulocTr) < 0) {
                return -1;
            }
        }
        return 0;
    }

    // Add one EF path to the thread sched and put the related partial-order constraints,
    //"endLocTr" is where "ep->dst" is finally used, we need such an end point to properly
    // assign the E/F nodes to the thread pool.
    // Return -1 if we think the E/F path is infeasible (e.g., a false alarm), 0 otherwise.
    int ThreadSched::addOneEFPath(EqvObjPair *ep, std::shared_ptr<InstLocTr> endLocTr) {
        if (!ep || !endLocTr) {
            return 0;
        }
        assert(endLocTr->getTr(this));
        std::shared_ptr<InstLocTr> currLoc = endLocTr, nextLoc = nullptr;
        // TODO: consider more/different eqv paths?
        EqvPath *epath = ep->getShortestEqvPath();
        if (epath && epath->path.size() > 0) {
            for (int i = epath->path.size() - 1; i >= 0; --i) {
                if (!currLoc) {
                    break;
                }
                // In each iteration we process one fetch node and its related escape node.
                std::shared_ptr<EqvPathNode> fnode = epath->path[i];
                if (!fnode) {
                    continue;
                }
                if (fnode->label != EqvPathNode::FETCH) {
                    // Update the target fetched object for the previous escape-fetch segment.
                    if (nextLoc) {
                        currLoc = nextLoc;
                        nextLoc = nullptr;
                    }
                    continue;
                }
                if (!fnode->pto || !fnode->pto->propagatingInst) {
                    continue;
                }
                Thread *ctr = currLoc->getTr(this);
                assert(ctr);
                // Theorem: the fetch node must sequentially reach the site using the fetched dummy obj.
                std::shared_ptr<InstLocTr> feLocTr = ctr->insertLoc(fnode->pto->propagatingInst,
                                            InstLocTr::TY_FETCH, true, false, nullptr, currLoc);
                if (!feLocTr) {
                    // Fail to insert current fetch node, this opposes the previous theorem,
                    // indicating that the control flow to trigger the bug is invalid.
                    return -1;
                }
                // Find the related escape node.
                int eidx = epath->getPairedIndex(i);
                if (eidx < 0) {
                    continue;
                }
                std::shared_ptr<EqvPathNode> enode = epath->path[eidx];
                if (!enode->pto || !enode->pto->propagatingInst) {
                    continue;
                }
                ObjectPointsTo *epto = enode->pto;
                // For this escape node, first we try to insert it before the related
                // fetch node in the same thread.
                std::shared_ptr<InstLocTr> esLocTr = ctr->insertLoc(epto->propagatingInst,
                                            InstLocTr::TY_ESCAPE, true, false, nullptr, feLocTr);
                if (!esLocTr) {
                    // It doesn't work... Then we try to insert it to other existing threads.
                    std::set<Thread*> blockTr;
                    blockTr.insert(ctr);
                    esLocTr = this->addLoc(enode->pto->propagatingInst,
                                           InstLocTr::TY_ESCAPE, &blockTr);
                }
                if (!esLocTr) {
                    // Seems impossible to fail this backup insertion...
                    // Maybe we need to give up this warning.
                    return -1;
                }
                // If we have to create a new thread to hold this escape node,
                // we will have to consider the question: in another entry invocation
                // for the "escape", is the escaped obj still the same as the original
                // one in the previous invocation?
                // E.g.,
                //  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                //  mc_irq = kcalloc(irq_count, sizeof(*mc_irq), GFP_KERNEL);
                //  if (ret) {
                //    kfree(mc_irq);  //FREE
                //    return ret;
                //  }
                //  vdev->mc_irqs = mc_irq; //ESCAPE
                //  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                //  In above snippet, the ESCAPE has to be performed in a different
                //  entry invocation than FREE's, where the escaped obj will be
                //  different than the freed (newly allocated heap obj per invocation).
                //  TODO: actually "escape in a new thread" is not necessary, it
                //  only requires "escape is in a different thread than the previous
                //  hop (might be free or fetch site)".
                Thread *esTr = esLocTr->getTr(this);
                if (esTr && esTr->seq.size() == 1 &&
                    !(esLocTr->ty & ~InstLocTr::TY_ESCAPE))
                {
                    AliasObject *eo = epto->targetObject;
                    if (eo && eo->isHeapLocationE() &&
                        _isPtoFromLocalPtr(epto,esLocTr->loc->ctx))
                    {
                        return -1;
                    }
                }
                if (!nextLoc) {
                    //"nextLoc" intends to record the leaf escaping object of current
                    // escape-fetch segment, which will also be the leaf fetched object
                    // of the previous escape-fetch segment.
                    nextLoc = esLocTr;
                }
                // TODO: consider to add "pto" records of f/e InstLocTr.
                // Add the partial-order constraint: the escape must happen before the
                // corresponding fetch.
                this->poc->addConstraint(esLocTr.get(), feLocTr.get());
            }
        }
        return 0;
    }

    int ThreadSched::addSyncPair(InstLoc *stLoc, InstLoc *edLoc, Thread *ptTr) {
        if (!stLoc || !edLoc || !ptTr ||
            std::find(this->trs.begin(),this->trs.end(),ptTr) == this->trs.end())
        {
            return 0;
        }
#ifdef DEBUG_ADD_SUPP_LOC
        dbgs() << "ThreadSched::addSyncPair(): inserting a pair of thread sync events.\n";
        dbgs() << "CREATE: ";
        stLoc->print_light(dbgs(), true);
        dbgs() << "JOIN: ";
        edLoc->print_light(dbgs(), true);
#endif
        //sync events should be outside the child pthread.
        std::set<Thread*> blocks{ptTr};
        while (true) {
            //First insert the CREATE event.
            int r0;
            std::shared_ptr<InstLocTr> stLocTr = this->addLoc(stLoc, InstLocTr::TY_TR_CREATE,
                                                              &blocks, false, false, &r0);
            if (!stLocTr) {
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "ThreadSched::addSyncPair(): failed to insert CREATE.\n";
#endif
                //No more threads in this sched to insert this CREATE event, exit.
                break;
            }
            //Next the JOIN event, into the same thread as CREATE.
            Thread *tr = stLocTr->getTr(this);
            assert(tr);
            int r1;
            std::shared_ptr<InstLocTr> edLocTr = tr->insertLoc(edLoc, InstLocTr::TY_TR_JOIN,
                                                               true, false, &r1, nullptr,
                                                               stLocTr);
            if (!edLocTr) {
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "ThreadSched::addSyncPair(): failed to insert JOIN.\n";
#endif
                //Roll back the insertion of CREATE.
                if (r0 != -2) {
                    tr->removeLoc(stLocTr, InstLocTr::TY_TR_CREATE);
                }
                //Try other threads in this sched.
                blocks.insert(tr);
                continue;
            }
            //Ok, both CREATE and JOIN have been successfully inserted.
            //Now we need to enforce the happens-before partial order constraints,
            //between "tr" (holding the sync events) and "ptTr" (the child pthread).
            //Basically, the child thread can only execute after CREATE but before JOIN.
            std::shared_ptr<InstLocTr> psLocTr = ptTr->getLoc(0);
            std::shared_ptr<InstLocTr> peLocTr = ptTr->getLoc(ptTr->seq.size() - 1);
            this->poc->addConstraint(stLocTr.get(), psLocTr.get());
            this->poc->addConstraint(peLocTr.get(), edLocTr.get());
#ifdef DEBUG_ADD_SUPP_LOC
            dbgs() << "ThreadSched::addSyncPair(): sync pair inserted.\n";
#endif
            //Try other threads.
            //TODO: is it really possible that the sync events can be inserted into
            //more than one thread?
            blocks.insert(tr);
        }
        return 1;
    }
    
    // Add the thread sync related InstLocs (e.g., fork, join) and add the related
    // happens-before partial order constraints.
    int ThreadSched::addSyncTrLocs() {
        //First see whether there are any trs in separate created threads (e.g., pthread_create())
        //with effective sync events (e.g., join()), we only need to consider sync locs when
        //there are such trs.
        for (Thread *tr : this->trs) {
            std::map<InstLoc*,std::set<InstLoc*>> rgs;
            this->gs->getCallbackRange(tr, rgs);
            //Next, try to insert the sync events to all applicable threads in this sched,
            //if no such threads exist, that means the trigering of this UAF may have
            //nothing to do with these sync events, so we can safely ignore them.
            for (auto &e : rgs) {
                if (!e.first || e.second.empty()) {
                    continue;
                }
                InstLoc *stLoc = e.first;
                for (InstLoc *edLoc : e.second) {
                    if (!edLoc) continue;
                    //Now try to insert stLoc and edLoc to all applicable threads.
                    this->addSyncPair(stLoc, edLoc, tr);
                }
            }
        }
        return 0;
    }

    // For each loc in the current threads, we try to add their surrounding lock/unlock
    // and global condition set/check locs. Note that this will be a recursive process,
    // e.g., a newly inserted lock node may also have its own surrounding condition
    // set/check, we need to add all relavent nodes until no more can be added.
    // RET: 0 for a normal return, negative if we decide the bug is infeasible and we
    // need to early terminate the validation process.
    int ThreadSched::addSuppTrLocs() {
        std::set<std::shared_ptr<InstLocTr>> currLocs, newLocs;
        // Basically a worklist algorithm.
        // Init the worklist with existing locs.
        for (Thread *tr : this->trs) {
            if (!tr) {
                continue;
            }
            for (auto &loc : tr->seq) {
                if (loc) {
                    currLocs.insert(loc);
                }
            }
        }
        // Find new relavent Locs for each loc in the list, recursively.
        int n_iter = 0, n_locs = 0;;
        while (!currLocs.empty()) {
#ifdef DEBUG_ADD_SUPP_LOC
            dbgs() << "addSuppTrLocs(): iteration " << n_iter << ", #locs to process: "
            << currLocs.size() << "\n"; 
#endif
            n_locs += currLocs.size();
            for (auto &loc : currLocs) {
                // Add surrounding lock/unlock locs.
                int r = this->addLockTrLocs(loc, newLocs);
                if (r < 0) {
                    //We need to early terminate the validation, impossible to trigger
                    //the bug.
                    return r;
                }
                // Add surrounding global condition set/check locs.
                r = this->addCondTrLocs(loc, newLocs);
                if (r < 0) {
                    //We need to early terminate the validation, impossible to trigger
                    //the bug.
                    return r;
                }
            }
            ++n_iter;
            // Before the next round, see whether we should stop to avoid too many locs.
#ifdef MAX_SUPP_LOC_ADD_ITERATION
            if (n_iter >= MAX_SUPP_LOC_ADD_ITERATION) {
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "addSuppTrLocs(): iteration limit reached!\n";
#endif
                break;
            }
#endif
#ifdef MAX_SUPP_LOC_ADD_NUM
            if (n_locs >= MAX_SUPP_LOC_ADD_NUM) {
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "addSuppTrLocs(): #locs limit reached!\n";
#endif
                break;
            }
#endif
            currLocs = newLocs;
            newLocs.clear();
        }
        // The condition set/check related partial-order constraints have been added
        // by the "addCondTrLocs()" function, but we still need to add the lock related
        // ones since only at this point we can have a global view of the lock/unlock
        // pairs.
        // Basically, we need to find all the critical regions (enclosed by a pair of
        // lock/unlock InstLocTr) guarded by the same lock objects, and then add the
        // mutual-exclusion partial-order constraints between them.
        std::vector<std::set<LockInfo *>> eqvLocks;
        for (auto &e : this->lockMap) {
            LockInfo *li = e.first;
            assert(li);
            // Find the eqv cluster of current LockInfo.
            bool has_eqv = false;
            for (unsigned i = 0; i < eqvLocks.size(); ++i) {
                for (LockInfo *li2 : eqvLocks[i]) {
                    if (this->gs->sameLockObjs(li, li2)) {
                        has_eqv = true;
                        break;
                    }
                }
                if (has_eqv) {
                    // Insert current LockInfo into the found eqv cluster.
                    eqvLocks[i].insert(li);
                    break;
                }
            }
            if (!has_eqv) {
                // Create a new eqv cluster for the unique LockInfo.
                eqvLocks.push_back(std::set<LockInfo *>());
                eqvLocks.back().insert(li);
            }
        }
        for (unsigned i = 0; i < eqvLocks.size(); ++i) {
            std::set<std::pair<std::shared_ptr<InstLocTr>, std::shared_ptr<InstLocTr>>> tmpPairs, *ppairs;
            if (eqvLocks[i].size() > 1) {
                for (LockInfo *li : eqvLocks[i]) {
                    tmpPairs.insert(this->lockMap[li].begin(), this->lockMap[li].end());
                }
                ppairs = &tmpPairs;
            } else {
                ppairs = &this->lockMap[*eqvLocks[i].begin()];
            }
            assert(ppairs);
            for (auto &e0 : *ppairs) {
                std::shared_ptr<InstLocTr> lk0 = e0.first;
                std::shared_ptr<InstLocTr> uk0 = e0.second;
                for (auto &e1 : *ppairs) {
                    std::shared_ptr<InstLocTr> lk1 = e1.first;
                    std::shared_ptr<InstLocTr> uk1 = e1.second;
                    if (lk0 != lk1 && uk0 != uk1) {
                        // Add the mutual-exclusion constraint: either region e0 executes
                        // before region e1, *or* the other way.
                        std::vector<void *> lk_cons{uk0.get(), lk1.get(), uk1.get(), lk0.get()};
                        this->poc->addConstraintOr(lk_cons);
                    }
                }
            }
        }
        return 0;
    }

    //Add the lock/unlock around the "loc" into its host thread, we assume
    //"loc" is within this thread sched.
    int ThreadSched::addLockTrLocs(std::shared_ptr<InstLocTr> loc, 
                                    std::set<std::shared_ptr<InstLocTr>> &newLocs) {
        if (!loc || !loc->loc) {
            return 0;
        }
        Thread *tr = loc->getTr(this);
        if (!tr) {
            return 0;
        }
#ifdef DEBUG_ADD_SUPP_LOC
        dbgs() << "ThreadSched::addLockTrLocs() for: ";
        loc->print(dbgs(), true);
#endif
        assert(std::find(this->trs.begin(), this->trs.end(), tr) != this->trs.end());
        // First get the lock/unlock locs.
        std::map<LockInfo *, std::set<LockInfo *>> lks;
        this->gs->getLock4Loc(loc->loc, lks);
        // Try to insert the lock/unlock locs to the thread.
        for (auto &e : lks) {
            LockInfo *linf = e.first;
            // TODO: should we consider every possible paired unlock?
            //(e.g., fork a separate thread for each pair).
            LockInfo *uinf = *(e.second.begin());
            assert(linf && uinf);
            InstLoc *lk = linf->loc;
            InstLoc *ulk = uinf->loc;
            assert(lk && ulk);
#ifdef DEBUG_ADD_SUPP_LOC
            dbgs() << "ThreadSched::addLockTrLocs(): one pair of lock/unlock identified:\n";
            dbgs() << "LOCK: ";
            lk->print_light(dbgs(), true);
            dbgs() << "UNLOCK: ";
            ulk->print_light(dbgs(), true);
#endif
            // Now insert this pair of lock/unlock into the thread.
            int r0;
            std::shared_ptr<InstLocTr> lkTr = tr->insertLoc(lk, InstLocTr::TY_LOCK,
                                                            true, false, &r0, loc);
            if (!lkTr) {
                // For some reasons we cannot insert the lock, so skip.
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "ThreadSched::addLockTrLocs(): cannot insert lock, skip.\n";
#endif
                continue;
            }
            // The Lock is in, now do the unlock, the unlock must be after "loc".
            int r1;
            std::shared_ptr<InstLocTr> ulkTr = tr->insertLoc(ulk, InstLocTr::TY_UNLOCK,
                                                             true, false, &r1, nullptr,
                                                             loc);
            if (!ulkTr) {
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "ThreadSched::addLockTrLocs(): cannot insert unlock, skip.\n";
#endif
                // Failed to insert the unlock, before skipping we also need
                // to remove the previously inserted lock if necessary.
                if (r0 != -2) {
                    tr->removeLoc(lkTr, InstLocTr::TY_LOCK);
                }
                continue;
            }
            // Both lock and unlock are in.
            // Record the lock pair information for future reference.
            std::pair<std::shared_ptr<InstLocTr>, std::shared_ptr<InstLocTr>> lkPair(lkTr, ulkTr);
            this->lockMap[linf].insert(lkPair);
            // Collect the newly created InstLocTr instances.
            if (r0 >= 0) {
                newLocs.insert(lkTr);
            }
            if (r1 >= 0) {
                newLocs.insert(ulkTr);
            }
        }
        return 0;
    }

    // Add the path condition set/check InstLocs around the specified "loc".
    // Ret: 0 if normal return, -1 if we should early terminate the UAF validation
    // due to an unresolvable pair of cond check/set (e.g., the killer set reaches
    // the cond check in a same thread). 
    int ThreadSched::addCondTrLocs(std::shared_ptr<InstLocTr> loc,
                                    std::set<std::shared_ptr<InstLocTr>> &newLocs) {
        if (!loc || !loc->loc) {
            return 0;
        }
        Thread *tr = loc->getTr(this);
        if (!tr) {
            return 0;
        }
        assert(std::find(this->trs.begin(), this->trs.end(), tr) != this->trs.end());
        //(1) Get all critical condition check for the loc.
        std::map<InstLoc *, unsigned> ccheck;
        loc->loc->getCriticalBranches(ccheck);
#ifdef DEBUG_ADD_SUPP_LOC
        dbgs() << "ThreadSched::addCondTrLocs() for: ";
        loc->print(dbgs(), false);
        dbgs() << ", #cond checks: " << ccheck.size() << "\n";
#endif
        //(2) Try to match the condition set with the identified checks.
        for (auto &e : ccheck) {
            InstLoc *cloc = e.first;
            assert(cloc);
            unsigned cdst = e.second;
            std::set<InstLoc *> klocs;
            this->gs->getCondKillerLocs(cloc, cdst, klocs);
            if (klocs.empty()) {
                // No killer locs found, skip.
                continue;
            }
#ifdef DEBUG_ADD_SUPP_LOC
            dbgs() << "ThreadSched::addCondTrLocs(): cond check InstLoc: ";
            cloc->print_light(dbgs(), false);
            dbgs() << ", dst: " << cdst << ", #klocs: " << klocs.size() << "\n";
#endif
            //(3) Try to insert the condition set/check locs into the thread.
            // Rule 1: add the cond check before "loc" within the same thread.
            // Note that cond check is ineviatable (e.g., dominates the "loc") by def.
            int rc;
            std::shared_ptr<InstLocTr> clocTr = tr->insertLoc(cloc, InstLocTr::TY_GCHECK,
                                                              true, false, &rc, loc);
            if (!clocTr) {
                // Failed to insert the cond check, skip.
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "ThreadSched::addCondTrLocs(): failed to insert cond check!\n";
#endif
                continue;
            }
            // Rule 2: add the cond set to any exsiting thread, but do not create new
            // ones for it.
            // TODO: in theory we should only insert ineviatable cond set into the
            // target thread, but our current eviatability test is merely based on
            // the CFG level dominance relationship w/o path sensitivity,
            // which may wrongly exclude some ineviatable cond sets.
            // So now we aggresively insert the cond set, trading some FN for less FP.
            bool has_kloc = false;
            for (InstLoc *kloc : klocs) {
                assert(kloc);
                int rk;
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "ThreadSched::addCondTrLocs(): process the killer loc: ";
                kloc->print_light(dbgs(), false);
#endif
                std::shared_ptr<InstLocTr> klocTr = tr->sched->addLoc(kloc,
                                        InstLocTr::TY_GSET, nullptr, false, false, &rk);
                if (!klocTr) {
#ifdef DEBUG_ADD_SUPP_LOC
                    dbgs() << ", insertion failed!\n";
#endif
                    continue;
                }
                Thread *kTr = klocTr->getTr(tr->sched);
                assert(kTr);
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << ", insertion succeeded!\n";
#endif
                if (tr->sched->_noKill(clocTr, klocTr)) {
#ifdef DEBUG_ADD_SUPP_LOC
                    dbgs() << "ThreadSched::addCondTrLocs(): kloc is not ineviatable,"
                    << " removed.\n";
#endif
                    if (rk != -2) {
                        kTr->removeLoc(klocTr, InstLocTr::TY_GSET);
                    }
                    continue;
                }
                //Can we make a decision that the kloc must kill the cloc?
                if (tr->sched->_mustKill(clocTr, klocTr)) {
#ifdef DEBUG_ADD_SUPP_LOC
                    //dbgs() << "ThreadSched::addCondTrLocs(): early signal of infeasibility, tr:\n";
                    //tr->print(dbgs());
#endif
                    return -1;
                }
                has_kloc = true;
                // If the killer has been created a new InstLocTr instance, record it.
                if (rk >= 0) {
                    newLocs.insert(klocTr);
                }
                // Add the partial-order cconstraint: The cond check must happen
                // before its killer so that the desired branch can be taken.
                this->poc->addConstraint(clocTr.get(), klocTr.get());
            }
            if (!has_kloc) {
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "ThreadSched::addCondTrLocs(): all killer locs fail the insertion!\n";
#endif
                // We do not have any killer locs, so it's also meaningless to keep the
                // cond check loc in the thread.
                if (rc != -2) {
                    tr->removeLoc(clocTr, InstLocTr::TY_GCHECK);
                }
                continue;
            }
            // Finally, don't forget to record the cond check loc if it's newly created.
            if (rc >= 0) {
                newLocs.insert(clocTr);
            }
            // Done, start processing the next cond check.
        }
        return 0;
    }

    bool ThreadSched::_mustKill(std::shared_ptr<InstLocTr> clocTr,
                                std::shared_ptr<InstLocTr> klocTr) {
        if (!clocTr || !klocTr) {
            return false;
        }
        //- If kill appears before check in a same thread, then it will
        //fail the partial order check obviously.
        Thread *tr = clocTr->getTr(this);
        if (!tr || tr != klocTr->getTr(this)) {
            return false;
        }
        auto itc = std::find(tr->seq.begin(), tr->seq.end(), clocTr);
        auto itk = std::find(tr->seq.begin(), tr->seq.end(), klocTr);
        return (int)(itk - itc) <= 0;
    }

    //Return true if we should discard the inserted kill loc for the cond check.
    bool ThreadSched::_noKill(std::shared_ptr<InstLocTr> clocTr,
                                std::shared_ptr<InstLocTr> klocTr) {
        if (!clocTr || !klocTr || !klocTr->loc) {
            return false;
        }
        //- If (1) kill appears before check in the same thread, and
        //(2) kill doesn't dominate check, and
        //(3) there is no other important events before kill (e.g., free).
        //Our insight is that it's less likely that the program will
        //code a dead path, so we will not immediately drop this warning.  
        Thread *tr = clocTr->getTr(this);
        if (!tr || tr != klocTr->getTr(this)) {
            return false;
        }
        auto itc = std::find(tr->seq.begin(), tr->seq.end(), clocTr);
        auto itk = std::find(tr->seq.begin(), tr->seq.end(), klocTr);
        if ((int)(itk - itc) > 0) {
            return false;
        }
        if (klocTr->loc->dom(clocTr->loc, false)) {
            return false;
        }
        /*
        if (itk != tr->seq.begin()) {
            return false;
        }
        */
        //Loose the above condition a bit: now only when there
        //are specific types of key statements (e.g., FREE)
        //before the killer loc, we consider that this LOC
        //will likely kill the cond check (e.g., as an associated
        //side-effects of FREE).
        if (itk != tr->seq.begin()) {
            for (auto it = tr->seq.begin(); it != itk && it != tr->seq.end(); ++it) {
                std::shared_ptr<InstLocTr> ltr = *it;
                if (ltr && ltr->ty == InstLocTr::TY_FREE) {
                    return false;
                }
            }
        }
        return true;
    }

    bool _isWithRefcnt(InstLoc *floc, InstLoc *uloc) {
        // Heuristic 1: see whether the F is inside a refcnt put function.
        static std::set<std::string> put_func_inc {
            "_put",
            "put_",
        };
        static std::set<std::string> get_func_inc {
            "_get",
            "get_",
        };
        if (floc) {
            std::vector<Instruction*> insts;
            if (dyn_cast<Instruction>(floc->inst)) {
                insts.push_back(dyn_cast<Instruction>(floc->inst));
            }
            if (floc->ctx && !floc->ctx->empty()) {
                insts.insert(insts.begin(),floc->ctx->callSites->begin(),floc->ctx->callSites->end());
            }
            for (int i = insts.size() - 1; i >= 0; --i) {
                Instruction *inst = insts[i];
                if (inst && inst->getParent() && inst->getFunction()) {
                    std::string func = inst->getFunction()->getName().str();
                    for (auto &s : put_func_inc) {
                        if (func.find(s) != std::string::npos) {
                            return true;
                        }
                    }
                }
                //Also check the func name from the dbg info, which can even
                //reveal the names of the inlined functions.
                if (i % 2) { 
                    std::vector<std::string> fns;
                    InstructionUtils::getHostFuncsFromDLoc(inst,fns);
                    for (auto &fn : fns) {
                        for (auto &s : put_func_inc) {
                            if (fn.find(s) != std::string::npos) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        // Heuristic 2: see whether F is dominated or post-dominated by a
        // refcnt change.
        // Here is a concerete example:
        /***********************************
        168:
        call void %166(%struct.atm_dev* noundef nonnull %141)
        //kfree() will be invoked inside this indirect function call
        br label %169

        169:
        %170 = getelementptr inbounds %struct.atm_dev, %struct.atm_dev* %141, i64 0, i32 18
        call void @put_device(%struct.device* noundef %170)
        //put_device() post-dominates the F site, indicating the refcnt based protection.
        ***********************************/
        // TODO
        // Heuristic 3: see whether U is guarded by a refcnt change.
        // TODO
        return false;
    }

    //If we can decide that the func ptr "p" can be derived from a certain
    //value in "srcs", return that value, otherwise nullptr. 
    Value *_isFptrFromCertainV(Value *p, std::set<Value*> &srcs) {
        if (!p || srcs.empty()) {
            return nullptr;
        }
        Value *np = p;
        while (np) {
            if (srcs.find(np) != srcs.end()) {
                return np;
            }
            np = InstructionUtils::stripAllCasts(np, false);
            if (srcs.find(np) != srcs.end()) {
                return np;
            }
            //TODO: may need to handle phi/select.
            if (dyn_cast<GetElementPtrInst>(np)) {
                np = dyn_cast<GetElementPtrInst>(np)->getPointerOperand();
            } else if (dyn_cast<LoadInst>(np)) {
                np = dyn_cast<LoadInst>(np)->getPointerOperand();
            } else {
                break;
            }
        }
        return nullptr;
    }

    //Similar to "_isFptrFromCertainV", but this tries to collect all
    //the origination values of "p" and collect them in res.
    void _getPtrSrcV(Value *p, std::set<Value*> &res) {
        Value *np = p;
        while (np) {
            res.insert(np);
            np = InstructionUtils::stripAllCasts(np, false);
            if (!np) {
                break;
            }
            res.insert(np);
            //TODO: may need to handle phi/select.
            if (dyn_cast<GetElementPtrInst>(np)) {
                np = dyn_cast<GetElementPtrInst>(np)->getPointerOperand();
            } else if (dyn_cast<LoadInst>(np)) {
                np = dyn_cast<LoadInst>(np)->getPointerOperand();
            } else {
                break;
            }
        }
        return;
    }

    //Decide whether the call site is an obj bound indirect call,
    //if true, return the obj pointer.
    Value *isOBIndCall(CallInst *ci) {
        static std::map<CallInst*,Value*> buf;
        //Basic sanity checks.
        if (!ci) {
            return nullptr;
        }
        //Ensure that it's an indirect call.
        Function *f = ci->getCalledFunction();
        if (f) {
            //An explicit function call.
            return nullptr;
        }
        //Get the func ptr.
        Value *fv = ci->getCalledOperand();
        if (!fv || dyn_cast<Function>(fv)) {
            return nullptr;
        }
        //Already processed?
        if (buf.find(ci) != buf.end()) {
            return buf[ci];
        }
        //Assume it's not.
        buf[ci] = nullptr;
        //Now decide whether this is an obj-bound indirect call,
        //basically we will see whether the func ptr is eventually
        //derived from an obj ptr which also appears as a func arg
        //(e.g., o->f(o,...)).
        //First get all the args.
        if (ci->arg_empty()) {
            //No args, less likely to be an obj-bound indirect call.
            return nullptr;
        }
        std::set<Value*> args;
        for (unsigned i = 0; i < ci->arg_size(); ++i) {
            _getPtrSrcV(ci->getArgOperand(i),args);
        }
        //Then trace back the ptr propagation history of "fv".
        Value *arg = _isFptrFromCertainV(fv, args);
        if (!arg) {
            //Not an obj-bound indirect call.
            return nullptr;
        }
        buf[ci] = arg;
        return arg;
    }

    class OBCallSiteInf {
    public:
        Function *f = nullptr;
        Value *obj = nullptr;
        std::map<ConstantAggregate*,std::set<long>> *constU = nullptr;
        std::map<Type*,std::set<long>> *mU = nullptr;
    };

    void getOBCallSitesFromCtx(CallContext *ctx, std::vector<OBCallSiteInf*> &res) {
        if (!ctx || !ctx->callSites) {
            return;
        }
        //Iterate through each call site.
        for (unsigned i = 1; i < ctx->callSites->size(); i += 2) {
            if (!dyn_cast<CallInst>(ctx->callSites->at(i))) {
                continue;
            }
            Value *po = isOBIndCall(dyn_cast<CallInst>(ctx->callSites->at(i)));
            if (!po) {
                continue;
            }
            //Get the target function.
            Instruction *ni = ctx->callSites->at(i+1);
            if (!ni || !ni->getParent()) {
                continue;
            }
            Function *f = ni->getFunction();
            if (!f) {
                continue;
            }
            OBCallSiteInf *obc = new OBCallSiteInf();
            obc->obj = po;
            obc->f = f;
            //The following results should have already been cached
            //during the main analysis, so should be fast.
            obc->constU = InstructionUtils::getUsesInGlobalConstStruct(f);
            obc->mU = InstructionUtils::getUsesInStruct(f);
            res.push_back(obc);
        }
        return;
    }

    bool _inDiffSTInstances(OBCallSiteInf *o0, OBCallSiteInf *o1) {
        if (!o0 || !o1 || !o0->constU || !o1->constU) {
            return false;
        }
        for (auto &e0 : *(o0->constU)) {
            ConstantAggregate *c0 = e0.first;
            if (!c0) {
                continue;
            }
            for (auto &e1 : *(o1->constU)) {
                ConstantAggregate *c1 = e1.first;
                if (!c1) {
                    continue;
                }
                if (c0 == c1) {
                    continue;
                }
                if (InstructionUtils::same_types(c0->getType(),c1->getType())) {
                    return true;
                }
            }
        }
        return false;
    }

    bool _atSameFieldType(OBCallSiteInf *o0, OBCallSiteInf *o1) {
        if (!o0 || !o1 || !o0->mU || !o1->mU) {
            return false;
        }
        for (auto &e0 : *(o0->mU)) {
            Type *ty0 = e0.first;
            if (!ty0) {
                continue;
            }
            for (auto &e1 : *(o1->mU)) {
                Type *ty1 = e1.first;
                if (!ty1) {
                    continue;
                }
                if (!InstructionUtils::same_types(ty0,ty1)) {
                    continue;
                }
                //Same types, then any same fields?
                for (long x : e0.second) {
                    if (e1.second.find(x) != e1.second.end()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    //Decide whether the calling contexts of "loc0" and "uloc1" both have an indirect
    //call site that is bound with a same typed object, but related with other.
    //(e.g., bound to different objects, thus the later U/F sites also target
    //unrelated objects).
    bool _hasUnrelObjBoundIndirectCalls(InstLoc *loc0, InstLoc *loc1) {
        if (!loc0 || !loc0->hasCtx() ||
            !loc1 || !loc1->hasCtx()) {
            return false;
        }
        //Step 1: individually collect the obj-bound indirect call sites
        //of loc0 and loc1, record info like obj type and the target func name.
        bool r = false;
        std::vector<OBCallSiteInf*> obc0, obc1;
        getOBCallSitesFromCtx(loc0->ctx, obc0);
        if (obc0.empty()) {
            goto exit;
        }
        getOBCallSitesFromCtx(loc1->ctx, obc1);
        if (obc1.empty()) {
            goto exit_0;
        }
        //Step 2: return true if the two contexts have indirect call sites
        //which are obj-bound but unrelated:
        //(1) two different target functions, AND
        //(2)-1 lie in two different struct instances of the same type
        //(indicating that the bound objs are different), OR
        //(2)-2 sit at the same field inside same-typed structs
        //(this will infer (2)-1).
        for (OBCallSiteInf *o0 : obc0) {
            for (OBCallSiteInf *o1 : obc1) {
                //(1)
                if (o0->f == o1->f) {
                    continue;
                }
                //(2)-1 or (2)-2
                if (_inDiffSTInstances(o0,o1) ||
                    _atSameFieldType(o0,o1))
                {
                    r = true;
                    goto exit_1;
                }
            }
        }
exit_1:
        for (OBCallSiteInf *p : obc1) {
            if (p) delete(p);
        }
exit_0:
        for (OBCallSiteInf *p : obc0) {
            if (p) delete(p);
        }
exit:
        return r;
    }

    // Pre_Cond: aloc is a heap allocation site, loc0 and loc1 both access this
    // allocation, this function tries to decide whether they may access the same
    // allocation instance from the CFG topology.
    // dir == 1: return false is all paths from loc0 to loc1 pass aloc, which means
    // loc1 must use a new allocation instance different from loc0.
    // dir == -1: same as above but the direction is from loc1 to loc0.
    // dir == 0: consider both directions.
    bool _canRefSameHeapObj(InstLoc *aloc, InstLoc *loc0, InstLoc *loc1, int dir) {
        if (!aloc || !loc0 || !loc1) {
            return false;
        }
        std::set<InstLoc *> blockers{aloc};
        bool r0 = (dir >= 0 ? loc1->reachable(loc0, &blockers) : false);
        bool r1 = (dir <= 0 ? loc0->reachable(loc1, &blockers) : false);
        return (r0 || r1);
    }

    void __printGEscape(std::vector<AliasObject*> &his, void *cp) {
        dbgs() << "Global Escape: ";
        for (auto &p : his) {
            dbgs() << (const void *)p << " -> ";
        }
        if (cp) {
            dbgs() << (const void *)cp;
        }
        dbgs() << "\n";
    }
    
    // Check whether "obj" can escape to any global memory at certain positions.
    // Args:
    // reflocs: the reference InstLoc sequence, used in combination with "pos",
    // if set to "nullptr", we consider obj escape at all possible locations.
    // pos:
    // -1: the escape should happen before the end of the sequence.
    //  1: happen after the beginning of the seq.
    //  0: can happen anywhere, as long as compatiable with the thread.
    //"pos" takes effects only when "refloc" is not nullptr.
    // Ret:
    //"true" if there are any global escape satisfying the requirements,
    //"false" otherwise.
    bool _hasGlobalEscape(std::vector<AliasObject*> &his, InstLoc *refloc,
                          Thread *reflocs, int pos) {
        if (his.empty() || !his.back()) {
            return false;
        } 
        AliasObject *obj = his.back();
        InstLoc *aloc = nullptr;
        obj->isHeapLocationE(&aloc);
        // Reasoning:
        //(1) for "PointerPointsTo" (top-level pointer variables pointing to this obj):
        //(1)-1, ptr is a global value (e.g., @g) -> this obj should have been created
        // as a GlobalObject at the very beginning (e.g., setupGlobals()), it's by def
        // a global escape.
        //(1)-2, otherwise ptr is a local value -> not a global escape.
        //(2) then for "pointsFrom" (other obj fields that point to "this"):
        //(2)-1: the pointsFrom obj is a local stack obj -> not a global escape.
        //(2)-2: the pointsFrom obj is a heap obj -> recursively see whether this
        // heap obj has any feasible global escapes.
        //(2)-3: other cases (e.g., global/outside objs) -> a global escape.
        //"pointerPointsTo"
        for (PointerPointsTo *pto : obj->pointersPointsTo) {
            if (pto && dyn_cast<GlobalValue>(pto->targetPointer)) {
                if (reflocs) {
                    InstLoc *eloc = pto->propagatingInst;
                    if (eloc && eloc->hasCtx() && !reflocs->testLocInSeq(eloc,pos)) {
                        // Position check fails, next.
                        continue;
                    }
                }
                // It's a global escape, the positioning is also ok.
                __printGEscape(his,pto->targetPointer);
                return true;
            }
        }
        //"pointsFrom"
        for (auto &e : obj->pointsFrom) {
            AliasObject *o = e.first;
            // NOTE: exclude self points-to since it is usually a linked list init.
            if (!o || o == obj) {
                continue;
            }
            if (o->isFunctionLocalE()) {
                continue;
            }
            if (std::find(his.begin(), his.end(), o) != his.end()) {
                // We have visited this (heap) obj before..
                continue;
            }
            // Potential global escape, but we need the position check,
            // also recursive check for the heap objs.
            bool is_heap = o->isHeapLocationE();
            if (reflocs) {
                std::set<InstLoc*> elocs;
                for (ObjectPointsTo *pto : e.second) {
                    if (pto) {
                        elocs.insert(pto->propagatingInst);
                    }
                }
                for (InstLoc *eloc : elocs) {
                    int prev_n_locs = reflocs->seq.size();
                    //Heap allocation modelling, basically, if the current to-escape "obj"
                    //is a heap allocation, we need to make sure that the instance used at
                    //the "refloc" is the same as that escapes at "eloc"..
                    if (eloc && aloc && refloc) {
                        if (!_canRefSameHeapObj(aloc, refloc, eloc, 0)) {
                            //The escaped is a different allocation instance...
                            continue;
                        }
                    }
                    if (eloc && eloc->hasCtx() && !reflocs->testLocInSeq(eloc,pos)) {
                        // Position check fails.
                        continue;
                    }
                    if (!is_heap) {
                        // Escape target is already a global mem, position also ok.
                        __printGEscape(his,o);
                        return true;
                    }
                    his.push_back(o);
                    // Escape to heap mem, we need to make sure that this heap
                    // obj also escapes with the same position requirements.
                    if (_hasGlobalEscape(his, eloc, reflocs, pos)) {
                        return true;
                    }
                    his.pop_back();
                    // Revert the thread state and try next eloc, if necessary.
                    if (reflocs->seq.size() > prev_n_locs) {
                        reflocs->removeLoc(eloc);
                    }
                }
            } else {
                if (!is_heap) {
                    __printGEscape(his,o);
                    return true;
                }
                his.push_back(o);
                if (_hasGlobalEscape(his, nullptr, nullptr, pos)) {
                    return true;
                }
                his.pop_back();
            }
        }
        return false;
    }

    bool _isPtoFromLocalPtr_ltag(ObjectPointsTo *pto, CallContext *ctx) {
        assert(pto);
        // First collect all the load insts leading to this pto,
        // e.g., the pointer might be obtained through multi-layer
        // memory indirection, like "o0->o1->o2->f", each layer
        // should be associated with a load inst and a load-from obj.
        std::map<InstLoc *, AliasObject *> loads;
        for (TypeField *tf : pto->loadTag) {
            if (!tf || !tf->v) {
                continue;
            }
            InstLoc *loc = (InstLoc *)(tf->v);
            LoadInst *li = dyn_cast<LoadInst>(loc->inst);
            if (li) {
                loads[loc] = (AliasObject *)(tf->priv);
            }
        }
        if (loads.empty()) {
            // The ptr is not loaded from memory, in this case there
            // is still one possibility that it's not a local ptr:
            // it originates from an arg of the top-level entry,
            // since we know little about the arg and its pointee.
            InstLoc *nloc = InstLoc::getLoc(pto->targetPointer, ctx, true);
            return (is_local_ptr(nloc) != -1);
        } else {
            // To be a local ptr, we need to ensure that every
            // layer of load is from local mem (e.g., stack obj),
            // otherwise the ptr is non-local.
            for (auto &e : loads) {
                AliasObject *o = e.second;
                if (o && o->isFunctionLocalE()) {
                    // The load-from obj is stack obj, safe...
                    continue;
                }
                InstLoc *loc = e.first;
                if (o && o->isHeapLocationE()) {
                    // If the src obj is a heap obj, we need to see whether
                    // it has ever been leaked (address-taken) to some shared
                    // memory prior to this load site, if not, that means
                    // there is no opportunity for other entry invocations
                    // to modify this heap obj to affect this load site,
                    // in other words, the loaded ptr should be purely
                    // formed within current invocation (locally).
                    std::vector<AliasObject*> his;
                    his.push_back(o);
                    Thread tr;
                    tr.insertLoc(loc);
                    if (!_hasGlobalEscape(his,loc,&tr,-1)) {
                        continue;
                    }
                }
                LoadInst *li = dyn_cast<LoadInst>(loc->inst);
                InstLoc *nloc = InstLoc::getLoc(li->getPointerOperand(), loc->ctx, true);
                // In theory the load-from obj in loadTag is already
                // enough for the decision, but to be safe we still
                // keep the check in the previous implementation as
                // an extra measure.
                if (is_local_ptr(nloc) > 0) {
                    continue;
                }
                // The load source is not local, so it's not a local ptr.
                return false;
            }
        }
        // We've checked all loads and all of them are from local source.
        return true;
    }

    bool _isSamePtr(Value *p0, Value *p1) {
        if (!p0 || !p1) {
            return (!p0 && !p1);
        }
        if (p0 == p1) {
            return true;
        }
        // Don't give up yet, it's also common that a ptr is regenerated
        // with GEP, even though a same-address ptr already existed.
        Value *np0 = InstructionUtils::stripAllCasts(p0, false);
        Value *np1 = InstructionUtils::stripAllCasts(p1, false);
        if (np0 && np1 &&
            dyn_cast<GEPOperator>(np0) &&
            dyn_cast<GEPOperator>(np1))
        {
            GEPOperator *gep0 = dyn_cast<GEPOperator>(np0);
            GEPOperator *gep1 = dyn_cast<GEPOperator>(np1);
            if (gep0->getNumOperands() != gep1->getNumOperands()) {
                return false;
            }
            for (unsigned i = 0; i < gep0->getNumOperands(); ++i) {
                Value *op0 = gep0->getOperand(i);
                Value *op1 = gep1->getOperand(i);
                if (op0 == op1) {
                    continue;
                }
                if (dyn_cast<ConstantInt>(op0) && dyn_cast<ConstantInt>(op1) &&
                    dyn_cast<ConstantInt>(op0)->getZExtValue() ==
                    dyn_cast<ConstantInt>(op1)->getZExtValue())
                {
                    continue;
                }
                return false;
            }
            //Two geps will result in the same ptr.
            return true;
        }
        return false;
    }

    bool _isPtoFromLocalPtr_prop(ObjectPointsTo *pto) {
        assert(pto);
        // The basic idea here is to inspect the propagating history
        // of this pto record, if we're sure that it originates from
        // an allocation site and doesn't involve any load from any
        // unknown shared memory, it's a local ptr.
        if (pto->propagatingHistory.empty()) {
            // Seems less likely.. but since there is not enough info
            // to make the decision, return false for conservativity.
            return false;
        }
        // Is the source an allocation site?
        // TODO: we may need a more accurate way to decide this.
        InstLoc *sloc = pto->propagatingHistory[0];
        if (!sloc || !dyn_cast<CallBase>(sloc->inst)) {
            return false;
        }
        // See whether the later pto propagation is in a local way.
        // We mainly care about whether there is any load from unknown
        // source, e.g., consecutive store and load for a same ptr
        // operand is ok.
        for (int i = pto->propagatingHistory.size() - 1; i > 0; --i) {
            InstLoc *loc = pto->propagatingHistory[i];
            if (loc && dyn_cast<LoadInst>(loc->inst)) {
                LoadInst *li = dyn_cast<LoadInst>(loc->inst);
                // We require that the preceding inst in the history
                // must be a store to the same mem location, in order
                // for this to be a local prop.
                if (i < 2) {
                    // Already no precedings.
                    return false;
                }
                InstLoc *ploc = pto->propagatingHistory[i-1];
                if (!ploc || !dyn_cast<StoreInst>(ploc->inst)) {
                    // The previous inst is not a store.
                    return false;
                }
                StoreInst *si = dyn_cast<StoreInst>(ploc->inst);
                if (!_isSamePtr(li->getPointerOperand(), si->getPointerOperand())) {
                    // load and store doesn't share the mem location.
                    return false;
                }
                --i;
            }
        }
        // We have inspected the propagating history and no signs of non-local
        // pointer propagation.
        return true;
    }
    
    bool _isPtoFromLocalPtr(ObjectPointsTo *pto, CallContext *ctx) {
        assert(pto);
        return _isPtoFromLocalPtr_ltag(pto,ctx);
    }

    // Decide whether "obj" accessed at "uloc" is obtained only through local
    // pointers (e.g., not loaded from some global objects).
    // Howto: the basic idea is to check the load tags, which record all the source
    // obj|fid a pto record has been generated from, if we do not see any global
    // objects in the load tag, we can conclude that the pto is from local pointers only.
    bool _isUseFromLocalPtr(InstLoc *uloc, AliasObject *obj) {
        if (!uloc || !obj) {
            return false;
        }
        std::set<PointerPointsTo *> ptos;
        obj->getUsePtos(uloc, ptos);
        // Pick out the pto record for the specified accessed "obj".
        for (PointerPointsTo *pto : ptos) {
            if (!pto) {
                continue;
            }
            //TODO: though less likely, what if there are multiple
            //pto records for the obj and they have different
            //"_isPtoFromLocalPtr()" decisions? Play it safe or
            //aggressively?
            return _isPtoFromLocalPtr(pto, uloc->ctx);
        }
        // To be conservative.
        return false;
    }

    //Similar to "_isUseFromLocalPtr", but just for the F site.
    bool _isFreeFromLocalPtr(InstLoc *floc, AliasObject *obj) {
        if (!floc || !obj) {
            return false;
        }
        std::set<PointerPointsTo*> *ptos = obj->getFreePtos(floc);
        if (!ptos) {
            return false;
        }
        // Pick out the pto record for the specified accessed "obj".
        for (PointerPointsTo *pto : *ptos) {
            if (!pto) {
                continue;
            }
            return _isPtoFromLocalPtr(pto, floc->ctx);
        }
        // To be conservative.
        return false;
    }
}