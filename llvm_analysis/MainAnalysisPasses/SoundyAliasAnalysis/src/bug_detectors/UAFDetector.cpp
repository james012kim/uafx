//
// Created by machiry on 12/27/16.
//

#include "bug_detectors/UAFDetector.h"
#include "bug_detectors/warnings/VulnerabilityWarning.h"

using namespace llvm;

namespace DRCHECKER {

#define DEBUG_LOAD_INSTR

    //This function decideds whether the data flow from the free site to the use site is valid (i.e., whether the
    //freed and the used are the same).
    //NOTE: we assume the "use" is under the current calling context of the UAFDetector.
    //RET: 0 if not valid.
    bool UAFDetector::isDataValid(AliasObject *useObj, InstLoc *freeLoc, AliasObject *freeObj) {
        if (this->allocLoc && this->useLoc) {
            //The data flow should be invalid if:
            //(1) the allocation site dominates the use site, and
            //(2) the free site cannot reach the use site.
            //Satisfying these conditions means that the use site always accesses a freshly allocated object instance,
            //which cannot be what is freed.
            if (this->allocLoc->dom(this->useLoc,false) && !this->useLoc->reachable(freeLoc)) {
                return false;
            }
        }
        //To be conservative, we treat the data flow as valid in other cases.
        //TODO: consider more cases where the data flow is invalid..
        return true;
    }

    //This mainly inspects whether the control flow from the free site to the use site is valid.
    //Currently we focus on the lockset analysis (e.g., when the control flow is concurrent).
    //TODO: take care of sequential control flow validation (e.g., with (cross-entry) symbolic execution).
    //NOTE: we assume the "use" is under the current calling context of the UAFDetector.
    //RET: 0 if not valid.
    bool UAFDetector::isControlValid(InstLoc *freeLoc) {
        if (!freeLoc) {
            //To be conservative..
            return true;
        }
        //A per-use cache mechanism for a better performance...
        for (auto &iter : this->ctlCache) {
            InstLoc *t = iter.first;
            if (freeLoc == t) {
                return ((int)(iter.second) == 0);
            }
        }
        this->ctlCache[freeLoc] = this->currState.holdSameLocks(freeLoc, this->useLoc);
        return (this->ctlCache[freeLoc] == 0);
    }

    void UAFDetector::visitLoadInst(LoadInst &I) {
#ifdef DEBUG_LOAD_INSTR
        dbgs() << "=== UAFDetector::visitLoadInst(): visit: " << InstructionUtils::getValueStr(&I) << "\n";
#endif
        //Basically, we check whether we're loading sth from a freed object, if so, we further check whether the control flow
        //from the free site to this load site (represents its 1st use) is valid.
        Value *srcPointer = I.getPointerOperand();
        std::set<PointerPointsTo*> *ptos = PointsToUtils::getPointsToObjects(this->currState, this->ctx, srcPointer);

        if (!ptos || ptos->empty()) {
            return;
        }
        this->ctlCache.clear();
        this->useLoc = InstLoc::getLoc(&I, this->ctx);
        //Record the free sites that are confirmed to form a valid UAF with the current use site.
        std::set<InstLoc*> confirmedFrees;
        for (PointerPointsTo *pto : *ptos) {
            if (!pto) {
                dbgs() << "!!! UAFDetector::visitLoadInst(): null pto!\n";
                continue;
            }
            //This is the "used" object..
            AliasObject *obj = pto->targetObject;
            if (!obj) {
                continue;
            }
            long fid = pto->dstfieldId;
            //TODO: whether to consider the allocation sites of its equivalent objects..
            this->allocLoc = obj->getFieldAllocSite(fid);
#ifdef DEBUG_LOAD_INSTR
            dbgs() << "--- UAFDetector::visitLoadInst(): use-obj: " << (const void*)obj << "|" << fid << ", allocLoc: ";
            if (this->allocLoc) {
                this->allocLoc->print_light(dbgs(),false);
            }
            dbgs() << "\n";
#endif
            //Get its equivalent objects -- our analysis is cross-entry.
            std::set<AliasObject*> eqvObjs;
            this->currState.getAllEquivelantObjs(obj, eqvObjs);
            //See whether any of these equivalent objects is freed somewhere...
            for (AliasObject *eo : eqvObjs) {
                if (!eo) {
                    continue;
                }
                std::set<InstLoc*> frees;
                eo->getFieldFreeSites(fid,frees);
                //Do some inspection to decide whether this is a valid UAF...
                for (InstLoc *loc : frees) {
                    if (!loc) {
                        continue;
                    }
#ifdef DEBUG_LOAD_INSTR
                    dbgs() << "EQV Obj: " << (const void*)eo << ", free site: ";
                    loc->print_light(dbgs(),false);
#endif
                    if (confirmedFrees.find(loc) != confirmedFrees.end()) {
                        //Already confirmed, no need to inspect again...
#ifdef DEBUG_LOAD_INSTR
                        dbgs() << " : Cached.\n";
#endif
                        continue;
                    }
                    //Validate the control flow..
                    if (!this->isControlValid(loc)) {
#ifdef DEBUG_LOAD_INSTR
                        dbgs() << " : Invalid Control.\n";
#endif
                        continue;
                    }
                    //Validate the data flow...
                    if (this->isDataValid(obj,loc,eo)) {
                        confirmedFrees.insert(loc);
#ifdef DEBUG_LOAD_INSTR
                        dbgs() << " : Valid.\n";
#endif
                    }else {
#ifdef DEBUG_LOAD_INSTR
                        dbgs() << " : Invalid Data.\n";
#endif
                    }
                }
            }
        }
        //Issue UAF warnings for the identified free sites and the current use site..
        for (InstLoc *loc : confirmedFrees) {
            std::vector<InstLoc*> *tr = new std::vector<InstLoc*>();
            tr->push_back(loc);
            std::string warningMsg = "Trying to load sth from a freed mem region.";
            VulnerabilityWarning *currWarning = new VulnerabilityWarning(
                                                            InstLoc::getLoc(&I,this->ctx),
                                                            tr, warningMsg, TAG);
            this->currState.addVulnerabilityWarning(currWarning);
        }
        return;
    }

    VisitorCallback* UAFDetector::visitCallInst(CallInst &I, Function *targetFunction,
                                                CallContext *oldCtx, CallContext *currCtx) {
        if (!targetFunction->isDeclaration()) {
            // only if the function has source.
            UAFDetector *newVis = new UAFDetector(this->currState, targetFunction, currCtx, nullptr);
            return newVis;
        }
        return nullptr;
    }

}
