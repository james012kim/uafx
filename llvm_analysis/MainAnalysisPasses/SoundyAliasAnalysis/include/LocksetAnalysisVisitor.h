//
// Created by hz on 05/08/21.
//

#ifndef PROJECT_LOCKSETANALYSISVISITOR_H
#define PROJECT_LOCKSETANALYSISVISITOR_H

#include "ModuleState.h"
#include "VisitorCallback.h"
#include "../../Utils/include/CFGUtils.h"
#include "../../Utils/include/LockInfo.h"
#include "../../LinuxKernelCustomizations/include/KernelFunctionChecker.h"
#include "PointsToUtils.h"

using namespace llvm;

namespace DRCHECKER {

    /***
     * The main class that implements the lockset analysis, which maintains the memory locking states.
     */
    class LocksetAnalysisVisitor : public VisitorCallback {

    public:
        GlobalState &currState;
        Function *targetFunction;

        // context of the analysis, basically list of call sites
        CallContext *ctx;

        // for querying the lock/unclock names, args, etc.
        static FunctionChecker *functionChecker;

        LocksetAnalysisVisitor(GlobalState &targetState,
                               Function *toAnalyze,
                               CallContext *srcCtx): currState(targetState) {
            this->targetFunction = toAnalyze;
            // Initialize the call site list
            this->ctx = srcCtx;
        }

        ~LocksetAnalysisVisitor() {
        }

        //virtual void visit(Instruction &I);

        virtual VisitorCallback* visitCallInst(CallInst &I, Function *targetFunction,
                                               CallContext *oldCtx,
                                               CallContext *currCtx);

    }; //LocksetAnalysisVisitor class definition

} //namespace DRCHECKER

#endif //PROJECT_LOCKSETANALYSISVISITOR_H
