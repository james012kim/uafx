//
// Created by Hang on 06/04/21.
//

#ifndef PROJECT_UAFDETECTOR_H
#define PROJECT_UAFDETECTOR_H 

#include <FunctionChecker.h>
#include "llvm/Pass.h"
#include "llvm/Analysis/AliasSetTracker.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/CFG.h"
#include "../VisitorCallback.h"
#include "../ModuleState.h"
#include "../PointsToUtils.h"

using namespace llvm;

namespace DRCHECKER {

    /***
     * This detector detects if any freed memory is being used.
     */
    class UAFDetector : public VisitorCallback {
    public:
        GlobalState &currState;
        Function *targetFunction;
        // context of the analysis, basically list of call sites
        CallContext *ctx;

        UAFDetector(GlobalState &targetState, Function *toAnalyze,
                    CallContext *ctx,
                    FunctionChecker *currChecker): currState(targetState) {
            this->targetFunction = toAnalyze;
            this->ctx = ctx;
            TAG = "UAFDetector says:";
        }

        // only function which we the current checker is interested in.
        virtual void visitLoadInst(LoadInst &I);
        virtual VisitorCallback* visitCallInst(CallInst &I, Function *targetFunction,
                                               CallContext *oldCtx, CallContext *currCtx);
        // For reducing false alarm UAFs...
        bool isDataValid(AliasObject *useObj, InstLoc *free, AliasObject *freeObj);
        bool isControlValid(InstLoc *freeLoc);
    private:
        std::string TAG;
        InstLoc *useLoc = nullptr;
        InstLoc *allocLoc = nullptr;
        std::map<InstLoc*,int> ctlCache;
    };
}

#endif //PROJECT_UAFDETECTOR_H
