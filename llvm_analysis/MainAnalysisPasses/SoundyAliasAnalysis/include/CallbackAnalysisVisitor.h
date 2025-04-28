#ifndef PROJECT_CALLBACKANALYSISVISITOR_H
#define PROJECT_CALLBACKANALYSISVISITOR_H

#include "ModuleState.h"
#include "VisitorCallback.h"
#include "../../Utils/include/CFGUtils.h"
#include "PointsToUtils.h"

using namespace llvm;

namespace DRCHECKER {

    /***
     * The analysis pass tries to identify callback functions registered in
     * the driver entries (e.g., bottom-half workqueue/tasklet functions)
     * and their arguments (e.g., work_struct), these callbacks in some
     * sense can also be viewed as driver entries, so we may also need to
     * analyze them after the entries manifested in the entry config.
     */
    class CallbackAnalysisVisitor : public VisitorCallback {

    public:
        GlobalState &currState;
        Function *targetFunction;

        // context of the analysis, basically list of call sites
        CallContext *ctx;

        CallbackAnalysisVisitor(GlobalState &targetState,
                                Function *toAnalyze,
                                CallContext *srcCtx): currState(targetState) {
            this->targetFunction = toAnalyze;
            // Initialize the call site list
            this->ctx = srcCtx;
        }

        ~CallbackAnalysisVisitor() {
        }

        //virtual void visit(Instruction &I);

        virtual void visitStoreInst(StoreInst &I);

        virtual VisitorCallback* visitCallInst(CallInst &I, Function *targetFunction,
                                               CallContext *oldCtx,
                                               CallContext *currCtx);
    private:
        //Adjust the pto in "ptos" to point to the start of the host struct "stn".
        std::set<PointerPointsTo*> *adjPto2Base(std::set<PointerPointsTo*> *ptos,
                                                std::string stn);

        void getFuncsFromValue(Value *v, std::set<Function*> &res);

        void add2GlobalRecords(std::set<Function*> *funcs, int f_cls, void *key,
                               CallBackInfo *cbi, Instruction *refInst);
    }; //CallbackAnalysisVisitor class definition

} //namespace DRCHECKER

#endif //PROJECT_CALLBACKANALYSISVISITOR_H
