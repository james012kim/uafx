//
// Created by machiry on 12/4/16.
//
#include <CFGUtils.h>
#include "PointsToUtils.h"
#include "GlobalVisitor.h"
#include "../../Utils/include/InstructionUtils.h"

namespace DRCHECKER {

    // Basic visitor functions.
    // call the corresponding function in the child callbacks.
    void GlobalVisitor::visitAllocaInst(AllocaInst &I) {
#ifdef TIMING_GLOB
        auto t0 = InstructionUtils::getCurTime();
#endif
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitAllocaInst(I);
        }
#ifdef TIMING_GLOB
        dbgs() << "[TIMING] GlobalVisitor::visitAllocaInst(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
    }

    void GlobalVisitor::visitCastInst(CastInst &I) {
#ifdef TIMING_GLOB
        auto t0 = InstructionUtils::getCurTime();
#endif
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitCastInst(I);
        }
#ifdef TIMING_GLOB
        dbgs() << "[TIMING] GlobalVisitor::visitCastInst(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
    }

    void GlobalVisitor::visitBinaryOperator(BinaryOperator &I) {
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitBinaryOperator(I);
        }
    }

    void GlobalVisitor::visitPHINode(PHINode &I) {
#ifdef TIMING_GLOB
        auto t0 = InstructionUtils::getCurTime();
#endif
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitPHINode(I);
        }
#ifdef TIMING_GLOB
        dbgs() << "[TIMING] GlobalVisitor::visitPHINode(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
    }

    void GlobalVisitor::visitSelectInst(SelectInst &I) {
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitSelectInst(I);
        }
    }

    void GlobalVisitor::visitGetElementPtrInst(GetElementPtrInst &I) {
#ifdef TIMING_GLOB
        auto t0 = InstructionUtils::getCurTime();
#endif
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitGetElementPtrInst(I);
        }
#ifdef TIMING_GLOB
        dbgs() << "[TIMING] GlobalVisitor::visitGetElementPtrInst(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
    }

    void GlobalVisitor::visitLoadInst(LoadInst &I) {
#ifdef TIMING_GLOB
        auto t0 = InstructionUtils::getCurTime();
#endif
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitLoadInst(I);
        }
#ifdef TIMING_GLOB
        dbgs() << "[TIMING] GlobalVisitor::visitLoadInst(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
    }

    void GlobalVisitor::visitStoreInst(StoreInst &I) {
#ifdef TIMING_GLOB
        auto t0 = InstructionUtils::getCurTime();
#endif
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitStoreInst(I);
        }
#ifdef TIMING_GLOB
        dbgs() << "[TIMING] GlobalVisitor::visitStoreInst(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
    }

    void GlobalVisitor::visitVAArgInst(VAArgInst &I) {
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitVAArgInst(I);
        }
    }

    void GlobalVisitor::visitVACopyInst(VACopyInst &I) {
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitVACopyInst(I);
        }
    }

    void GlobalVisitor::visitReturnInst(ReturnInst &I) {
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitReturnInst(I);
        }
    }

    void GlobalVisitor::visitICmpInst(ICmpInst &I) {
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitICmpInst(I);
        }
    }

    void GlobalVisitor::visitBranchInst(BranchInst &I) {
#ifdef TIMING_GLOB
        auto t0 = InstructionUtils::getCurTime();
#endif
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitBranchInst(I);
        }
#ifdef TIMING_GLOB
        dbgs() << "[TIMING] GlobalVisitor::visitBranchInst(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
    }

    //hz: add support for switch inst.
    void GlobalVisitor::visitSwitchInst(SwitchInst &I) {
#ifdef TIMING_GLOB
        auto t0 = InstructionUtils::getCurTime();
#endif
        for(VisitorCallback *currCallback:allCallbacks) {
            currCallback->visitSwitchInst(I);
        }
#ifdef TIMING_GLOB
        dbgs() << "[TIMING] GlobalVisitor::visitSwitchInst(): ";
        InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
    }

//A hacking: set up a blacklist for certain time-consuming functions..
#ifdef FUNC_BLOCKLIST
    bool GlobalVisitor::isFuncBlocked(std::string &fname) {
        static std::set<std::string> block_funcs{
            "con_write", "do_con_write", "io_serial_out", "io_serial_in", "emulation_required", "ccci_dump_write",
            "part_read", "part_write", "part_read_user_prot_reg", "part_write_user_prot_reg", "part_read_fact_prot_reg",
            "part_panic_write", "concat_read", "concat_lock", "concat_unlock", "part_lock", "part_unlock", "part_is_locked",
            "mtd_lock", "mtd_unlock", "part_lock_user_prot_reg", "is_set_plane_size", "do_8051_command",
            "__mdiobus_write", "__mdiobus_read", "read_dev_port_cntr", "write_dev_port_cntr",
            "_config_display_some_debug"};
        static std::set<std::string> block_funcs_inc{
            "asan_report",
            "llvm.dbg",
            "__sanitizer_cov_trace_pc",
            "printf",
            "_wreg",
            "_rreg",
            "_access_virt",
            "qib_portcntr_",
        };
        if (block_funcs.find(fname) != block_funcs.end()) {
            return true;
        }
        for (auto &x : block_funcs_inc) {
            if (fname.find(x) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
#endif

    void GlobalVisitor::processCalledFunction(CallInst &I, Function *currFunc) {
#ifdef TIMING_GLOB
        auto t0 = InstructionUtils::getCurTime();
#endif
        std::string currFuncName = currFunc->getName().str();
        std::vector<Instruction*> *currCallSites = this->ctx->callSites;
        // Create new context.
        //Set up arguments of the called function.
        std::vector<Instruction*> newCallSites;
        newCallSites.insert(newCallSites.end(), currCallSites->begin(), currCallSites->end());
        // create context.
        newCallSites.insert(newCallSites.end(), &I);
        //hz: If this is an indirect call inst, there can be multiple possible target callees, in this situation
        //if we only insert the call inst itself into the "call context", we will not be able to differentiate
        //these target callees... So now for each call inst, we insert both the call inst and the entry inst of the
        //target function into the "call context".
        if (!currFunc->isDeclaration()) {
#ifdef DEBUG_CALL_INSTR
            dbgs() << "GlobalVisitor::processCalledFunction: prepare context for: " << currFuncName << " (w/ definition)\n";
#endif
            BasicBlock &bb = currFunc->getEntryBlock();
            newCallSites.insert(newCallSites.end(), bb.getFirstNonPHIOrDbg());
        }else{
            //Insert the call inst again in order to match the 2*MAX-1...
#ifdef DEBUG_CALL_INSTR
            dbgs() << "GlobalVisitor::processCalledFunction: prepare context for: " << currFuncName << " (w/o definition)\n";
#endif
            newCallSites.insert(newCallSites.end(), &I);
        }
        CallContext *newCtx = this->currState.getOrCreateContext(&newCallSites);
        assert(newCtx != nullptr);

        // new callbacks that handles the current function.
        std::vector<VisitorCallback*> newCallBacks;

        // map of the parent visitor to corresponding child visitor.
        std::map<VisitorCallback*, VisitorCallback*> parentChildCallBacks;

        for (VisitorCallback *currCallback : allCallbacks) {
            VisitorCallback *newCallBack = currCallback->visitCallInst(I, currFunc, this->ctx, newCtx);
            if(newCallBack != nullptr) {
                newCallBacks.insert(newCallBacks.end(), newCallBack);
                parentChildCallBacks[currCallback] = newCallBack;
            }
        }
#ifdef TIMING_GLOB
        dbgs() << "[TIMING] GlobalVisitor::visitCallInst(): ";
        InstructionUtils::getTimeDuration(t0, &dbgs());
#endif
        // if there are new call backs? then create a GlobalVisitor and run the corresponding  visitor
        if (newCallBacks.size() > 0) {
            // Make sure we have the function definition.
            assert(!currFunc->isDeclaration());
#ifdef DEBUG_CALL_INSTR
            dbgs() << "Analyzing new function: " << currFuncName << " Call depth: " << newCallSites.size() << "\n";
#endif
            //log the current calling context.
            dbgs() << "CTX: ";
            InstructionUtils::printCallingCtx(dbgs(),&newCallSites,true);
#ifdef TIMING
            dbgs() << "[TIMING] Start func(" << newCallSites.size() << ") " << currFuncName << ": ";
            auto t1 = InstructionUtils::getCurTime(&dbgs());
#endif
            std::vector<std::vector<BasicBlock *> *> *traversalOrder = BBTraversalHelper::getSCCTraversalOrder(*currFunc);
            // Create a GlobalVisitor
            GlobalVisitor *vis = new GlobalVisitor(currState, currFunc, newCtx, traversalOrder, newCallBacks);
            // Start analyzing the function.
            vis->analyze();

            // stitch back the contexts of all the member visitor callbacks.
            for(std::map<VisitorCallback *, VisitorCallback *>::iterator iter = parentChildCallBacks.begin();
                iter != parentChildCallBacks.end();
                ++iter)
            {
                VisitorCallback *parentCallback = iter->first;
                VisitorCallback *childCallback = iter->second;
                parentCallback->stitchChildContext(I, childCallback);
                delete(childCallback);
            }
            delete(vis);
#ifdef TIMING
            dbgs() << "[TIMING] End func(" << newCallSites.size() << ") " << currFuncName << " in: ";
            double func_secs = InstructionUtils::getTimeDuration(t1,&dbgs());
            //Update the timing stats.
            auto &tmap = this->currState.funcTime;
            if (tmap.find(currFunc) != tmap.end() &&
                tmap[currFunc].find(DRCHECKER::currEntryFunc) != tmap[currFunc].end())
            {
                tmap[currFunc][DRCHECKER::currEntryFunc].first++;
                tmap[currFunc][DRCHECKER::currEntryFunc].second += func_secs;
            } else {
                tmap[currFunc][DRCHECKER::currEntryFunc].first = 1;
                tmap[currFunc][DRCHECKER::currEntryFunc].second = func_secs;
            }
#endif
            //log the current calling context.
            dbgs() << "CTX: ";
            InstructionUtils::printCallingCtx(dbgs(),currCallSites,true);
        }
    }

    //Get the possible callee of "I", the main challenge lies in indirect calls.
    int GlobalVisitor::_getCallTargets(CallInst &I, std::set<Function*> &tgts) {
        tgts.clear();
        //Is there an explicit target callee?
        Function *currFunc = I.getCalledFunction();
        if (currFunc == nullptr) {
            // this is to handle casts.
            currFunc = dyn_cast<Function>(I.getCalledOperand()->stripPointerCasts());
        }
        if (currFunc != nullptr) {
            //Nice just a normal call site w/o boring ptrs...
            tgts.insert(currFunc);
            return 1;
        }
        //Resolve the indirect call site, the major reasoning work should have
        //been done by the alias analysis already.
#ifdef DEBUG_CALL_INSTR
        dbgs() << "Indirect call site detected: " << InstructionUtils::getValueStr(&I) << "\n";
#endif
        //if this is inline assembly, ignore the call instruction.
        if (I.isInlineAsm()) {
            //TODO: inline asm is really a headache in LLVM IR analysis,
            //we should consider about possible solutions!
            return 0;
        }
        Value *calledValue = I.getCalledOperand();
        //get points to information of calledValue and look for only functions.
        PointsToUtils::getTargetFunctions(this->currState, this->ctx, calledValue, tgts);
#ifdef SMART_FUNCTION_PTR_RESOLVING
        if (tgts.empty()) {
            // NOTE: the below inference is actually a backup method to the "getPossibleMemeberFunction" when
            // we fetch the field pto from an object, so if we are sure that the aforementioned inference
            // has already been performed (and we still get nothing), then no need to do the inference again here.
            Value *v = InstructionUtils::stripAllCasts(calledValue, false);
            if (v && dyn_cast<LoadInst>(v)) {
                // We must have already tried the inference when processing the "load", so give up now.
                dbgs() << "Alias analysis has done the inference previously,"
                << " but no luck...\n";
                return 0;
            }
            InstructionUtils::getPossibleFunctionTargets(I, tgts);
#ifdef DEBUG_CALL_INSTR
            dbgs() << "#func targets identified by the backup method: " << tgts.size() << "\n";
#endif
            if (tgts.size() > MAX_FUNC_PTR) {
#ifdef DEBUG_CALL_INSTR
                dbgs() << "Too many targets, randomly drop some, our limit: " << MAX_FUNC_PTR << "\n";
#endif
                std::set<Function*> tset = tgts;
                tgts.clear();
                for (Function *f : tset) {
                    if (tgts.size() >= MAX_FUNC_PTR) {
                        break;
                    }
                    if (f) {
                        tgts.insert(f);
                    }
                }
            }
        }
#endif
        return tgts.size();
    }
    
    void GlobalVisitor::visitCallInst(CallInst &I) {
#ifdef DEBUG_CALL_INSTR
        dbgs() << "GlobalVisitor::visitCallInst(): " << InstructionUtils::getValueStr(&I) << "\n";
#endif
        if (this->inside_loop) {
#ifdef DEBUG_CALL_INSTR
            dbgs() << "GlobalVisitor::visitCallInst(): Function inside loop,"
            << " will be analyzed at last iteration\n";
#endif
            return;
        }
        //Get the target callee(s).
        std::set<Function*> tgts;
        this->_getCallTargets(I, tgts);
        if (tgts.empty()) {
#ifdef DEBUG_CALL_INSTR
            dbgs() << "GlobalVisitor::visitCallInst(): no callees identified!\n";
#endif
            return;
        }
        //CallInst location based recursive/repeat check.
        //(1) Is the callsite already visited before in the same ctx (e.g., loops)?
        bool visited_in_loop = (this->visitedCallSites.find(&I) != this->visitedCallSites.end());
        this->visitedCallSites.insert(&I);
        //(2) Is the exact same callsite visited before in the call chain (e.g., recursive)?
        std::vector<Instruction*> *cs = this->ctx->callSites;
        bool visited_recur = false;
        //Match the historical callsites with current one.
        for (unsigned i = 1; i < cs->size(); i += 2) {
            if (&I == cs->at(i)) {
                visited_recur = true;
                break;
            }
        }
        //Call stack depth check.
        bool exceed_stack_limit = false;
#ifdef DONOT_CARE_COMPLETION
        //NOTE: we need to use "2*MAX-1" since for each call site we insert both the
        //call inst and the callee entry inst into the context.
        exceed_stack_limit = (cs->size() > 2 * MAX_CALLSITE_DEPTH - 1);
#endif
#ifdef DEBUG_CALL_INSTR
        dbgs() << "GlobalVisitor::visitCallInst(): visited_in_loop: " << visited_in_loop
        << ", visited_recur: " << visited_recur << ", exceed_stack_limit: " 
        << exceed_stack_limit << ", #targets: " << tgts.size() << "\n";
#endif
        //Visit each callee if applicable.
        for (Function *func : tgts) {
            if (!func) {
                continue;
            }
            //If the function has a body, before diving into it we want to:
            //(1) avoid the recursive/repeat cases to avoid call chain explosion;
            //(2) honor the limit on the max call stack depth.
            //Otherwise if it's only a declaration, we can probably handle
            //it anyway since we simply model it, which is cheap and fast.
            if (!func->isDeclaration()) {
                if (exceed_stack_limit || visited_in_loop || visited_recur) {
                    continue;
                }
            }
            //Is the function blocked?
            std::string fname = func->getName().str();
#ifdef FUNC_BLOCKLIST
            if (GlobalVisitor::isFuncBlocked(fname)) {
#ifdef DEBUG_CALL_INSTR
                dbgs() << "GlobalVisitor::visitCallInst(): callee blocked: " << fname << "\n";
#endif
                continue;
            }
#endif
            //Additionally, also perform a function name based recursion
            //detection, which can capture some missing cases by "visited_recur",
            //e.g., we do visit the same function twice in a call chain but
            //with different call sites - it's also a recursion!
            //As long as this happens, it's possibly due to the inaccuracy of
            //our indirect call resolution, as it's less likely for kernel
            //to have such recursion.
            //NOTE: if the same-name function exsits in the call chain already,
            //it must have a body (i.e., !func->isDeclaration()).
            unsigned i = 0;
            for (; i < cs->size(); i += 2) {
                if ((*cs)[i] && (*cs)[i]->getParent()) {
                    Function *cfunc = (*cs)[i]->getFunction();
                    if (cfunc && cfunc->getName().str() == fname) {
                        break;
                    }
                }
            }
            if (i < cs->size()) {
#ifdef DEBUG_CALL_INSTR
                dbgs() << "GlobalVisitor::visitCallInst(): callee exists in the chain: "
                << fname << "\n";
#endif
                continue;
            }
            //Check whether we should skip for performance reasons.
            if (!func->isDeclaration() && this->_shouldSkipForPerf(func)) {
#ifdef DEBUG_CALL_INSTR
                dbgs() << "GlobalVisitor::visitCallInst(): skip callee for performance: "
                << fname << "\n";
#endif
                continue;
            }
            //Finally, we can go ahead to process this callee..
            this->processCalledFunction(I, func);
        }
        return;
    }

    bool GlobalVisitor::_shouldSkipForPerf(Function *func) {
#ifdef TIMING
        if (this->currState.funcTimeLimit > 0) {
            auto &tmap = this->currState.funcTime;
            if (tmap.find(func) != tmap.end() &&
                tmap[func].find(DRCHECKER::currEntryFunc) != tmap[func].end())
            {
                double total = InstructionUtils::getTimeDuration(this->currState.t_start, nullptr);
                if (total >= 3600 * 8.0 &&
                    tmap[func][DRCHECKER::currEntryFunc].first >= 5 &&
                    tmap[func][DRCHECKER::currEntryFunc].second >= 1800.0)
                {
                    return true;
                }
            }
        }
        return false;
#elif
        return false;
#endif
    }

    void GlobalVisitor::visit(BasicBlock *BB) {
        if(this->currState.numTimeAnalyzed.find(BB) != this->currState.numTimeAnalyzed.end()) {
#ifdef FAST_HEURISTIC
            if(this->currState.numTimeAnalyzed[BB] >= GlobalVisitor::MAX_NUM_TO_VISIT) {
#ifdef DEBUG_BB_VISIT
                dbgs() << "Ignoring BB:" << InstructionUtils::getValueStr(BB)
                       << " ad it has been analyzed more than:"
                       << GlobalVisitor::MAX_NUM_TO_VISIT << " times\n";
#endif
                return;
            }
#endif
            this->currState.numTimeAnalyzed[BB] = this->currState.numTimeAnalyzed[BB] + 1;
        } else {
            this->currState.numTimeAnalyzed[BB] = 1;
        }
#ifdef DEBUG_BB_VISIT
        dbgs() << "Starting to analyze BB:" <<  InstructionUtils::getBBStrID(BB)
        << ":at:"<< InstructionUtils::getValueStr(BB->getParent()) << "\n";
#endif
        for(VisitorCallback *currCallback : allCallbacks) {
            currCallback->visit(BB);
        }
#ifdef SKIP_ASAN_INST
        for (Instruction &inst : *BB) {
            if (InstructionUtils::isAsanInst(&inst)) {
                dbgs() << "GlobalVisitor::visit(): Skip ASAN inst: " << InstructionUtils::getValueStr(&inst) << "\n";
                continue;
            }
            _super->visit(inst);
        }
#else
        _super->visit(BB->begin(), BB->end());
#endif
    }

    void GlobalVisitor::analyze() {
        // the traversal order should not be null
        assert(this->traversalOrder != nullptr);
        for (unsigned int i = 0; i < this->traversalOrder->size(); i++) {
            // current strongly connected component.
            std::vector<BasicBlock*> *currSCC = (*(this->traversalOrder))[i];
            if (currSCC->size() == 1) {
                BasicBlock* currBB = (*currSCC)[0];
                if (!this->currState.isDeadBB(this->ctx,currBB)) {
                    this->inside_loop = false;
                    for(VisitorCallback *currCallback:allCallbacks) {
                        currCallback->setLoopIndicator(false);
                    }
                    //Analyzing single basic block.
                    this->visit(currBB);
                }else {
                    //Current BB is infeasible
#ifdef DEBUG_GLOBAL_ANALYSIS
                    dbgs() << "GlobalVisitor::analyze(): skip the BB since it's infeasible: " 
                    << InstructionUtils::getBBStrID(currBB) << "\n"; 
#endif
                }
            }else {
                unsigned long opt_num_to_analyze = BBTraversalHelper::getNumTimesToAnalyze(currSCC);
#ifdef HARD_LOOP_LIMIT
                if (MAX_LOOP_CNT < opt_num_to_analyze) {
                    opt_num_to_analyze = MAX_LOOP_CNT;
                }
#endif
#ifdef DEBUG_GLOBAL_ANALYSIS
                dbgs() << "Analyzing Loop BBS for:" << opt_num_to_analyze << " number of times\n";
#endif
                this->inside_loop = true;
                for (VisitorCallback *currCallback:allCallbacks) {
                    currCallback->setLoopIndicator(true);
                }
                for (unsigned int l=0; l < opt_num_to_analyze; l++) {
                    // ensure that loop has been analyzed minimum number of times.
                    if(l >= (opt_num_to_analyze-1)) {
                        this->inside_loop = false;
                        for(VisitorCallback *currCallback:allCallbacks) {
                            currCallback->setLoopIndicator(false);
                        }
                    }
                    for (unsigned int j = 0; j < currSCC->size(); j++) {
                        BasicBlock *currBB = (*currSCC)[j];
                        if (!this->currState.isDeadBB(this->ctx,currBB)) {
                            this->visit(currBB);
                        }else {
#ifdef DEBUG_GLOBAL_ANALYSIS
                            dbgs() << "GlobalVisitor::analyze(): skip the BB (in a loop) since it's infeasible: " 
                            << InstructionUtils::getBBStrID(currBB) << "\n"; 
#endif
                        }
                    }
                }
#ifdef DEBUG_GLOBAL_ANALYSIS
                dbgs() << "Analyzing Loop BBS END\n";
#endif
                //Analyzing loop.
            }
        }
    }
}