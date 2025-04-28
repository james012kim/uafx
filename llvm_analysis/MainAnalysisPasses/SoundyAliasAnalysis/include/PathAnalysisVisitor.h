//
// Created by hz on 8/13/20.
//

#ifndef PROJECT_PATHANALYSISVISITOR_H
#define PROJECT_PATHANALYSISVISITOR_H

#include "ModuleState.h"
#include "VisitorCallback.h"
#include "../../Utils/include/CFGUtils.h"
#include "../../Utils/include/Constraint.h"

using namespace llvm;

namespace DRCHECKER {

    /***
     * The main class that implements the path analysis, which makes the static analysis partially path-sensitive,
     * e.g. it can detect some infeasible paths according to the path conditions, or collect path constraints.
     */
    class PathAnalysisVisitor : public VisitorCallback {

    public:
        GlobalState &currState;
        Function *targetFunction;

        // context of the analysis, basically list of call sites
        CallContext *ctx;

        PathAnalysisVisitor(GlobalState &targetState,
                            Function *toAnalyze,
                            CallContext *srcCtx): currState(targetState) {
            this->targetFunction = toAnalyze;
            // Initialize the call site list
            this->ctx = srcCtx;
        }

        ~PathAnalysisVisitor() {
        }

        //virtual void visit(Instruction &I);

        virtual void visitSwitchInst(SwitchInst &I);

        virtual void visitBranchInst(BranchInst &I);

        virtual VisitorCallback* visitCallInst(CallInst &I, Function *targetFunction,
                                               CallContext *oldCtx,
                                               CallContext *currCtx);

        virtual void visitPHINode(PHINode &I);

        virtual void visitCastInst(CastInst &I);

    private:
        // Calculate the context-insensitive constraints for I.
        Constraint *_visitSwitchInst_ctx_free(SwitchInst &I);

        // Calculate the context-insensitive constraints for I.
        Constraint *_visitBranchInst_ctx_free(BranchInst &I);

        void _propConstraints4Cast(CastInst &I, Constraint *cs, Constraint *cd);

        void _visitSwitchInst(SwitchInst &I);

        void _visitBranchInst(BranchInst &I);

        void _visitPHINode(PHINode &I);

        VisitorCallback* _visitCallInst(CallInst &I, Function *targetFunction,
                                       CallContext *oldCtx,
                                       CallContext *currCtx);

    }; //PathAnalysisVisitor class definition

} //namespace DRCHECKER

#endif //PROJECT_PATHANALYSISVISITOR_H
