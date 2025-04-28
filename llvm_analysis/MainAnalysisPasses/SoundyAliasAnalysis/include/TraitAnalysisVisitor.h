#ifndef PROJECT_TRAITANALYSISVISITOR_H
#define PROJECT_TRAITANALYSISVISITOR_H

#include "ModuleState.h"
#include "VisitorCallback.h"
#include "../../Utils/include/CFGUtils.h"
#include "../../Utils/include/Constraint.h"
#include "PointsToUtils.h"
#include "Trait.h"

using namespace llvm;

namespace DRCHECKER {

    /***
     * The analysis pass that decides the relationship between condition set and check,
     * e.g., set a global flag to true can kill the check of it against false.
     */
    class TraitAnalysisVisitor : public VisitorCallback {

    public:
        GlobalState &currState;
        Function *targetFunction;

        // context of the analysis, basically list of call sites
        CallContext *ctx;

        TraitAnalysisVisitor(GlobalState &targetState,
                             Function *toAnalyze,
                             CallContext *srcCtx): currState(targetState) {
            this->targetFunction = toAnalyze;
            // Initialize the call site list
            this->ctx = srcCtx;
        }

        ~TraitAnalysisVisitor() {
        }

        //virtual void visit(Instruction &I);

        virtual void visitSwitchInst(SwitchInst &I);

        virtual void visitBranchInst(BranchInst &I);

        virtual void visitStoreInst(StoreInst &I);

        virtual VisitorCallback* visitCallInst(CallInst &I, Function *targetFunction,
                                               CallContext *oldCtx,
                                               CallContext *currCtx);
    private:
        TraitSet *getStorePattern(StoreInst &I);

        std::pair<TraitCheck*,Value*> *getBrChkPattern(BranchInst &I);

        //Given a Value*, try to decide its origin, like an obj|fid, or a return value.
        int traceCondOrigin(Value *v, std::map<void*, std::set<long>> &res);

        void _visitBranchInst(BranchInst &I);
    }; //TraitAnalysisVisitor class definition

} //namespace DRCHECKER

#endif //PROJECT_TRAITANALYSISVISITOR_H
