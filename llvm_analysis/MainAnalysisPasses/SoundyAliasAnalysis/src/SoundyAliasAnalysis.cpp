//
// Created by machiry on 10/24/16.
//
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/ValueSymbolTable.h"
#include "ModuleState.h"
#include <AliasObject.h>
#include <iostream>
#include <fstream>
#include <llvm/Analysis/CallGraph.h>
#include <FunctionChecker.h>
#include <CFGUtils.h>
#include <AliasFuncHandlerCallback.h>
#include <llvm/Analysis/LoopInfo.h>
#include "AliasAnalysisVisitor.h"
#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IR/Module.h"
#include "KernelFunctionChecker.h"
#include "GlobalVisitor.h"
#include "llvm/Support/CommandLine.h"
#include "bug_detectors/BugDetectorDriver.h"
#include "PointsToUtils.h"
#include <chrono>
#include <ctime>
#include <thread>
#include <mutex>
#include <sys/time.h>
#include <unistd.h>
#include "PathAnalysisVisitor.h"
#include "LocksetAnalysisVisitor.h"
#include "TraitAnalysisVisitor.h"
#include "CallbackAnalysisVisitor.h"


using namespace llvm;

namespace DRCHECKER {

//#define DEBUG_SCC_GRAPH
//#define DEBUG_TRAVERSAL_ORDER
//#define DEBUG_GLOBAL_VARIABLES
//#define DEBUG_GLOBAL_TAINT
#define DEBUG_UAF_DETECT

#define NETDEV_IOCTL "NETDEV_IOCTL"
#define READ_HDR "READ_HDR"
#define WRITE_HDR "WRITE_HDR"
#define IOCTL_HDR "IOCTL_HDR"
#define DEVATTR_SHOW "DEVSHOW"
#define DEVATTR_STORE "DEVSTORE"
#define V4L2_IOCTL_FUNC "V4IOCTL"
#define NULL_ARG "NULL_ARG"
#define MY_IOCTL "MY_IOCTL"

    std::map<Value *, std::set<PointerPointsTo*>*> GlobalState::globalVariables;
    std::map<Function *, std::set<BasicBlock*>*> GlobalState::loopExitBlocks;

    FunctionHandlerCallback* AliasAnalysisVisitor::callback = new AliasFuncHandlerCallback();
    FunctionHandler* AliasAnalysisVisitor::functionHandler = new FunctionHandler(new KernelFunctionChecker());
    //FunctionChecker* TaintAnalysisVisitor::functionChecker = nullptr;
    FunctionChecker* LocksetAnalysisVisitor::functionChecker = nullptr;

    static cl::opt<std::string> checkFunctionName("toCheckFunction",
                                              cl::desc("Function which is to be considered as entry point "
                                                               "into the driver"),
                                              cl::value_desc("full name of the function"), cl::init(""));

    static cl::opt<std::string> functionType("functionType",
                                              cl::desc("Function Type. \n Linux kernel has different "
                                                               "types of entry points from user space.\n"
                                                               "Specify the type of entry function."),
                                              cl::value_desc("Function Type"), cl::init(""));

    static cl::opt<unsigned> skipInit("skipInit", cl::desc("Skip analyzing init functions."),
                                       cl::value_desc("long, non-zero value indicates, skip initialization function"),
                                       cl::init(1));

    static cl::opt<unsigned> funcTimeLimit("funcTimeLimit",
            cl::desc("Skip frequently appearing functions that take too much time."),
            cl::value_desc("long, non-zero value indicates enabling the opt."),
            cl::init(0));

    static cl::opt<unsigned> eqvObjTimeLimit("eqvObjTimeLimit",
            cl::desc("Limit the time spending on eqv obj enumeration."),
            cl::value_desc("long, non-zero value indicates enabling the opt."),
            cl::init(0));

    static cl::opt<std::string> outputFile("outputFile",
                                            cl::desc("Path to the output file, where all the warnings should be stored."),
                                            cl::value_desc("Path of the output file."), cl::init(""));

    static cl::opt<std::string> instrWarnings("instrWarnings",
                                              cl::desc("Path to the output file, where all the warnings w.r.t instructions should be stored."),
                                              cl::value_desc("Path of the output file."), cl::init(""));

    static cl::opt<std::string> entryConfig("entryConfig",
                                              cl::desc("Config file that specifies all entry functions to be analyzed and the related information like type and user arg"),
                                              cl::value_desc("The path of the config file"), cl::init(""));

    typedef struct FuncInf {
        std::string name;
        Function *func;
        std::string ty;
        std::vector<int> user_args;
    } FuncInf;

    static std::vector<FuncInf*> targetFuncs;

    void printCurTime() {
        auto t_now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(t_now);
        dbgs() << std::ctime(&now_time) << "\n";
    }

    class MemoryMonitor {
       public:
        MemoryMonitor(int interval_seconds)
            : interval(interval_seconds), running(true), paused(false), memUsageIdx(0) {}

        void start() {
            worker = std::thread([this]() {
                while (running) {
                    if (!paused) {
                        memRecHandler();
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(interval));
                }
            });
        }

        void stop() {
            running = false;
            if (worker.joinable()) {
                worker.join();
            }
        }

        void pause() {
            paused = true;
        }

        void resume() {
            paused = false;
        }

        ~MemoryMonitor() {
            stop();
        }

        void printMemStatistics(bool incr = false) {
            printCurTime();

            std::lock_guard<std::mutex> lock(vec_mutex);
            if (memoryUsages.empty()) return;

            size_t id0 = (incr ? memUsageIdx : 0);
            size_t id1 = memoryUsages.size() - 1;
            memUsageIdx = id1;

            double min = *std::min_element(memoryUsages.begin() + id0, memoryUsages.end());
            double max = *std::max_element(memoryUsages.begin() + id0, memoryUsages.end());
            double average = std::accumulate(memoryUsages.begin() + id0, memoryUsages.end(), 0.0) / (id1 - id0 + 1);
            // Make a copy for computing median
            std::vector<double> memoryUsagesCopy(id1 - id0 + 1);
            std::copy(memoryUsages.begin() + id0, memoryUsages.end(), memoryUsagesCopy.begin());
            std::sort(memoryUsagesCopy.begin(), memoryUsagesCopy.end());
            double median = (memoryUsagesCopy.size() % 2 == 0) ? (memoryUsagesCopy[memoryUsagesCopy.size() / 2 - 1] + memoryUsagesCopy[memoryUsagesCopy.size() / 2]) / 2.0
                                                               : memoryUsagesCopy[memoryUsagesCopy.size() / 2];
            dbgs() << "Memory Usage Statistics (in MB):\n";
            dbgs() << "Min: " << min << "\n";
            dbgs() << "Max: " << max << "\n";
            dbgs() << "Average: " << average << "\n";
            dbgs() << "Median: " << median << "\n";
        }

        private:
        int interval;
        std::atomic<bool> running, paused;
        std::thread worker;
        std::vector<double> memoryUsages;
        size_t memUsageIdx = 0;
        mutable std::mutex vec_mutex;

        void memRecHandler() {
            std::ifstream statm("/proc/self/statm");
            if (!statm.is_open()) {
                dbgs() << "!!! Unable to open /proc/self/statm.\n";
                return;
            }
            unsigned long size, resident, share, text, lib, data, dt;
            statm >> size >> resident >> share >> text >> lib >> data >> dt;
            statm.close();

            long pageSize = sysconf(_SC_PAGESIZE);
            double memoryUsageMB = (resident * pageSize) / (1024.0 * 1024.0);  // Convert to MB

            printCurTime();
            dbgs() << "[MEM] Current Memory Usage: " << memoryUsageMB << " MB.\n";
            
            std::lock_guard<std::mutex> lock(vec_mutex);
            this->memoryUsages.push_back(memoryUsageMB);
        }
    };

    struct SAAPass: public ModulePass {
    public:
        static char ID;
        //GlobalState moduleState;

        CallGraph *callgraph;
        FunctionChecker *currFuncChecker;

        SAAPass() : ModulePass(ID) {
            currFuncChecker = new KernelFunctionChecker();
        }

        ~SAAPass() {
            delete(currFuncChecker);
        }

		//Copied from online source...
        std::vector<std::string> split(const std::string& str, const std::string& delim) {
    		std::vector<std::string> tokens;
    		size_t prev = 0, pos = 0;
    		do{
        		pos = str.find(delim, prev);
        		if (pos == std::string::npos) pos = str.length();
        		std::string token = str.substr(prev, pos-prev);
        		if (!token.empty()) tokens.push_back(token);
        		prev = pos + delim.length();
    		}while (pos < str.length() && prev < str.length());
    		return tokens;
		}

        Function *getFuncByName(Module &m, std::string &name) {
            for (Function &f : m) {
                if (f.hasName() && f.getName().str() == name) {
                    return &f;
                }
            }
            return nullptr;
        }

        void getTargetFunctions(Module &m) {
            if (checkFunctionName.size() > 0) {
                //Method 0: specify a single entry function.
                FuncInf *fi = new FuncInf();
                fi->name = checkFunctionName;
                fi->func = getFuncByName(m,checkFunctionName);
                //The user arg number might be encoded in the type string if it's MY_IOCTL.
                if (functionType.find(MY_IOCTL) == 0) {
                    fi->ty = MY_IOCTL; 
                    //Get the encoded user arg information.
                    std::vector<std::string> tks = split(functionType,"_");
                    if (tks.size() > 2) {
                        for (int i = 2; i < tks.size(); ++i) {
                            //NOTE: Exceptions may occur if the invalid arg is passed-in.
                            int idx = std::stoi(tks[i]);
                            fi->user_args.push_back(idx);
                        }
                    }
                }else {
                    fi->ty = functionType;
                }
                targetFuncs.push_back(fi);
            }else if (entryConfig.size() > 0) {
                //Method 1: specify one or multiple functions in a config file, together w/ related information like type.
                //Line format:
                //<func_name>
                //* opt opt_arg0 opt_arg1 ...
                std::ifstream ifile;
                ifile.open(entryConfig);
                std::string l;
                while (std::getline(ifile, l)) {
                    //Skip the comment line
                    if (l.find("#") == 0) {
                        continue;
                    }
                    std::vector<std::string> tks = split(l," ");
                    if (tks.size() >= 2 && tks[0] == "*") {
                        //An option line.
                        if (tks[1] == "XENTRY_SHARED_OBJ") {
                            for (int i = 2; i < tks.size(); ++i) {
                                DRCHECKER::sharedObjTyStrs.insert(tks[i]);
                            }
                        }else {
                            //The option is not supported.
                            dbgs() << "Unrecognized option: " << l << "\n";
                        }
                    }else if (tks.size() >= 1) {
                        FuncInf *fi = new FuncInf();
                        fi->name = tks[0];
                        fi->func = getFuncByName(m,tks[0]);
                        targetFuncs.push_back(fi);
                    }else {
                        dbgs() << "Invalid line in the entry config file: " << l << "\n";
                    }
                }
                ifile.close();
            }else {
                //No entry functions specified.
                dbgs() << "getTargetFunctions(): No entry functions specified!\n";
                return;
            }
            //debug output
            dbgs() << "getTargetFunctions: Functions to analyze:\n";
            for (FuncInf *fi : targetFuncs) {
                dbgs() << "FUNC: " << fi->name << " PTR: " << (const void*)fi->func << " TYPE: " << fi->ty << " USER_ARGS:";
                for (int i : fi->user_args) {
                    dbgs() << " " << i;
                }
                dbgs() << "\n";
            }
            return;
        }

        //For any global variable that is used by our specified function(s), find all ".init" functions that also use the same GV.
        //************HZ***********
        //TODO: consider to encode our domain knowledge about the driver interface here, e.g. if the target function is an .ioctl,
        //we can try to identify its related .open and driver .probe in this function, as these functions will possibly do some
        //initializations for some internal shared states like file->private.
        //************HZ***********
        void getAllInterestingInitFunctions(Module &m, std::string currFuncName,
                                            std::set<Function*> &interestingInitFuncs) {
            /***
             * Get all init functions that should be analyzed to analyze provided init function.
             */
            Module::GlobalListType &currGlobalList = m.getGlobalList();
            std::set<llvm::GlobalVariable*> currFuncGlobals;
            bool is_used_in_main;
            std::set<Function*> currFuncs;
            for(Module::global_iterator gstart = currGlobalList.begin(), gend = currGlobalList.end();
                    gstart != gend; gstart++) {
                llvm::GlobalVariable *currGlob = &*gstart;
                currFuncs.clear();
                is_used_in_main = false;
                for(auto cu:currGlob->users()) {
                    Instruction *currInst = dyn_cast<Instruction>(cu);
                    if(currInst != nullptr && currInst->getParent() && currInst->getParent()->getParent()) {
                        Function *currFunc = currInst->getParent()->getParent();
                        if(currFunc->hasName()) {
                            if(currFunc->getName() == currFuncName) {
                                is_used_in_main = true;
#ifdef DEBUG_GLOBAL_VARIABLES
                                dbgs() << "Global variable:" << *gstart << " used in function:" << currFuncName << "\n";
#endif
                            } else {
                                if(currFuncChecker->is_init_function(currFunc)) {
                                    currFuncs.insert(currFunc);
                                }
                            }
                        }
                    }
                }
                //"currFuncs" contains all _init_ functions that have used current gv, 
                //"is_used_in_main" indicates whether current gv is used in the target function to analyze.
                //The assumption here is that we will never use an _init_ function as the target function.
                if(is_used_in_main && currFuncs.size()) {
                    for(auto cg:currFuncs) {
                        if(interestingInitFuncs.find(cg) != interestingInitFuncs.end()) {
                            interestingInitFuncs.insert(cg);
                        }
                    }
                }

            }

        }

        bool runOnModule(Module &m) override {

            FunctionChecker* targetChecker = new KernelFunctionChecker();
            // create data layout for the current module
            DataLayout *currDataLayout = new DataLayout(&m);
            mSlotTracker = new ModuleSlotTracker(&m);

            GlobalState currState(currDataLayout);
            // set the read and write flag in global state, to be used by differect detectors.
            //TODO: this should be moved to the bug detect phase for every entry function.
            currState.is_read_write_function = functionType == READ_HDR || functionType == WRITE_HDR;
            // propagate the user global options..
            currState.funcTimeLimit = funcTimeLimit;
            DRCHECKER::MAX_EQV_OBJ_ENUM_CNT = eqvObjTimeLimit;
            // set pointer to global state
            AliasAnalysisVisitor::callback->setPrivateData(&currState);
            // setting function checker(s).
            //TaintAnalysisVisitor::functionChecker = targetChecker;
            AliasAnalysisVisitor::callback->targetChecker = targetChecker;
            LocksetAnalysisVisitor::functionChecker = targetChecker;

            // Setup aliases for global variables.
            setupGlobals(m);
            //hz: taint all global objects, field-sensitive.
            //addGlobalTaintSource(currState);

            //Get the target functions to be analyzed.
            getTargetFunctions(m);

            // Set a periodic timer to record the memory usage.
            MemoryMonitor mm(30);
            mm.start();
                        
            auto t_start = std::chrono::system_clock::now();
            currState.t_start = t_start;
            dbgs() << "[TIMING] Analysis starts at: ";
            printCurTime();
            // Call init functions.
            //hz: this is a lightweight (i.e. only includes alias analysis) analysis for the init functions (e.g. .open and .probe), 
            //the goal is to set up some preliminary point-to records used in the real target functions.
            dbgs() << "=========================Preliminary Analysis Phase=========================\n";
            currState.analysis_phase = 1;
            if (!skipInit) {
                std::set<Function*> toAnalyzeInitFunctions;
                for (FuncInf *fi : targetFuncs) {
                    getAllInterestingInitFunctions(m, fi->name, toAnalyzeInitFunctions);
                }
                dbgs() << "Analyzing: " << toAnalyzeInitFunctions.size() << " init functions\n";
                for(auto currInitFunc : toAnalyzeInitFunctions) {
                    dbgs() << "CTX: " << currInitFunc->getName() << " ->\n";
#ifdef TIMING
                    dbgs() << "[TIMING] Start func(1) " << currInitFunc->getName() << ": ";
                    auto t0 = InstructionUtils::getCurTime(&dbgs());
#endif
                    printCurTime();
                    std::vector<std::vector<BasicBlock*>*> *traversalOrder =
                            BBTraversalHelper::getSCCTraversalOrder(*currInitFunc);

                    std::vector<Instruction*> callSites;
                    callSites.push_back(currInitFunc->getEntryBlock().getFirstNonPHIOrDbg());
                    CallContext *initContext = currState.getOrCreateContext(&callSites);
                    assert(initContext != nullptr);

                    VisitorCallback *aliasVisitorCallback = new AliasAnalysisVisitor(currState, currInitFunc, initContext);
                    VisitorCallback *pathVisitorCallback = new PathAnalysisVisitor(currState, currInitFunc, initContext);

                    std::vector<VisitorCallback*> allCallBacks;
                    allCallBacks.push_back(aliasVisitorCallback);
                    allCallBacks.push_back(pathVisitorCallback);

                    GlobalVisitor *vis = new GlobalVisitor(currState, currInitFunc, initContext, traversalOrder,
                                                           allCallBacks);

                    DRCHECKER::currEntryFunc = currInitFunc;

                    vis->analyze();
#ifdef TIMING
                    dbgs() << "[TIMING] End func(1) " << currInitFunc->getName() << " in: ";
                    InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
                    //Clean up the global visitor.
                    delete(vis);
                }
            }
            //Analyze the entries specified in the config file.
            auto t_prev = std::chrono::system_clock::now();
            auto t_next = t_prev;
            dbgs() << "=========================Main Analysis Phase (Entry)=========================\n";
            currState.analysis_phase = 2;
            for (FuncInf *fi : targetFuncs) {
                if (!fi || !fi->func || fi->func->isDeclaration()) {
                    dbgs() << "!!! runOnModule(): (!fi || !fi->func || fi->func->isDeclaration())\n";
                    continue;
                }
                Function &currFunction = *(fi->func);

                std::vector<std::vector<BasicBlock *> *> *traversalOrder =
                BBTraversalHelper::getSCCTraversalOrder(currFunction);
#ifdef DEBUG_TRAVERSAL_ORDER
                std::cout << "Got Traversal order For: " << currFunction.getName().str() << "\n";
                BBTraversalHelper::printSCCTraversalOrder(traversalOrder,&dbgs());
#endif
#ifdef DEBUG_SCC_GRAPH
                InstructionUtils::dumpFuncGraph(&currFunction);
#endif
                // first instruction of the entry function, used in the initial calling context.
                std::vector<Instruction*> callSites;
                callSites.push_back(currFunction.getEntryBlock().getFirstNonPHIOrDbg());
                CallContext *initContext = currState.getOrCreateContext(&callSites);
                assert(initContext != nullptr);
                // set up user function args, e.g. pto, initial taint.
                // No need to do this now since user args are no longer taint source for UAF detection, pto will also be set up
                // in a lazy way.
                //setupFunctionArgs(fi, currState, initContext);

                std::vector<VisitorCallback *> allCallBacks;
                // first add all analysis visitors.
                addAllVisitorAnalysis(currState, &currFunction, initContext, &allCallBacks, false);
                // create global visitor and run it.
                GlobalVisitor *vis = new GlobalVisitor(currState, &currFunction,
                                            initContext, traversalOrder, allCallBacks);
                dbgs() << "CTX: " << fi->name << " ->\n";
#ifdef TIMING
                dbgs() << "[TIMING] Start func(1) " << fi->name << ": ";
                auto t0 = InstructionUtils::getCurTime(&dbgs());
#endif
                DRCHECKER::currEntryFunc = &currFunction;
                vis->analyze();

#ifdef TIMING
                dbgs() << "[TIMING] End func(1) " << fi->name << " in: ";
                InstructionUtils::getTimeDuration(t0,&dbgs());
#endif
                //Record the timestamp.
                t_next = std::chrono::system_clock::now();
                std::chrono::duration<double> elapsed_seconds = t_next - t_prev;
                dbgs() << "[TIMING] Anlysis of " << fi->name << " done in : "
                << elapsed_seconds.count() << "s\n";
                t_prev = t_next;

                //clean up
                dbgs() << "[TIMING] Clean up GlobalVisitor at: ";
                printCurTime();
                delete (vis);
            }
            //Analyze the callbacks (e.g., bottom-half interrupt handlers) identified
            //during the analysis of the major entries in the last phase.
            t_prev = std::chrono::system_clock::now();
            t_next = t_prev;
            dbgs() << "=========================Main Analysis Phase (Callback)=========================\n";
            //First print out the list of the identified callbacks to analyze.
            dbgs() << "The identified callbacks to be analyzed:\n";
            currState.printCallbacks(dbgs());
            for (auto &e0 : currState.callbacks) {
                int f_cls = e0.first;
                for (auto &e1 : e0.second) {
                    Function *func = e1.first;
                    if (!func || func->isDeclaration()) {
                        continue;
                    }
                    std::vector<std::vector<BasicBlock *> *> *traversalOrder =
                        BBTraversalHelper::getSCCTraversalOrder(*func);
                    //Prepare the calling context.
                    std::vector<Instruction*> callSites;
                    callSites.push_back(func->getEntryBlock().getFirstNonPHIOrDbg());
                    CallContext *initCtx = currState.getOrCreateContext(&callSites);
                    assert(initCtx != nullptr);
                    //Set up the arg pto records.
                    this->setupCallbackArgs(currState, initCtx, func, f_cls, e1.second);
                    //Add the required analysis passes.
                    //We currently assume that callbacks will no longer
                    //register more callbacks, so disabling the callback analysis pass.
                    std::vector<VisitorCallback*> allCallBacks;
                    addAllVisitorAnalysis(currState, func, initCtx, &allCallBacks, false);
                    // create global visitor and run it.
                    GlobalVisitor *vis = new GlobalVisitor(currState, func,
                                                initCtx, traversalOrder, allCallBacks);
                    std::string fname = func->getName().str();
                    dbgs() << "CTX: " << fname << " ->\n";
#ifdef TIMING
                    dbgs() << "[TIMING] Start func(1) " << fname << ": ";
                    auto t0 = InstructionUtils::getCurTime(&dbgs());
#endif
                    DRCHECKER::currEntryFunc = func;
                    vis->analyze();
#ifdef TIMING
                    dbgs() << "[TIMING] End func(1) " << fname << " in: ";
                    InstructionUtils::getTimeDuration(t0, &dbgs());
#endif
                    // Record the timestamp.
                    t_next = std::chrono::system_clock::now();
                    std::chrono::duration<double> elapsed_seconds = t_next - t_prev;
                    dbgs() << "[TIMING] Anlysis of " << fname << " done in : "
                    << elapsed_seconds.count() << "s\n";
                    t_prev = t_next;

                    // clean up
                    dbgs() << "[TIMING] Clean up GlobalVisitor at: ";
                    printCurTime();
                    delete (vis);
                }
            }
            auto t_now = std::chrono::system_clock::now();
            std::chrono::duration<double> elapsed_seconds = t_now - t_start;
            dbgs() << "[TIMING] Main Analysis Phase finished in : " << elapsed_seconds.count() << "s\n";
            dbgs() << "[MEM] Mem Statistics for Main Analysis Phase:\n";
            mm.printMemStatistics();
            //Bug detection phase: traverse all the code (for every entry function) again and detect potential bugs along the way.
            //We need to have a separate traversal because we want to detect high-order taint bugs, 
            //so we must wait until all analysis have been done.
            dbgs() << "=========================Bug Detection Phase=========================\n";
#ifdef TIMING
            dbgs() << "[TIMING] Bug Detection Phase Starts : ";
            auto tb = InstructionUtils::getCurTime(&dbgs());
#endif
            currState.analysis_phase = 3;
            detectUAFs(currState);
#ifdef TIMING
            dbgs() << "[TIMING] Bug Detection Phase finished in : ";
            InstructionUtils::getTimeDuration(tb,&dbgs());
#endif
            dbgs() << "[MEM] Mem Statistics for Bug Detection Phase:\n";
            mm.printMemStatistics(true);
            // clean up.
            // TODO: the finalization seems have some bugs (likely double-free, ironically...)
            // we need to debug and fix this later (including major deconstructors like ~AliasObject)
            // For now we comment the code out, since anyway the whole process will exit.
            // explicitly delete references to global variables.
            /*
            dbgs() << "Clean up global state at: ";
            printCurTime();
            currState.cleanup();
            dbgs() << "Clean up DataLayout at: ";
            printCurTime();
            delete(currDataLayout);
            delete(mSlotTracker);
            */
            dbgs() << "All done: ";
            printCurTime();
            dbgs() << "[MEM] Mem Statistics for All:\n";
            mm.printMemStatistics();
            exit(0);
            return true;
        }

    private:

        //Generate and issue Type I UAF warnings: the freed object escape-fetch
        //(forward) to the used object.
        //Args:
        //"fo": the freed object.
        //"frees": the free sites (InstLocs).
        void _detectUAFS_ty1(GlobalState &state, AliasObject *fo,
                                std::set<InstLoc*> &frees) {
            if (!fo || frees.empty()) {
                return;
            }
            //Basically, find all forward eqv objects of the freed object, and gather
            //their use sites if any.
            std::map<AliasObject *, EqvObjPair *> feqv;
            fo->getForwardEqvObjs(feqv);
            for (auto &e : feqv) {
                AliasObject *feo = e.first;
                EqvObjPair *fep = e.second;
                // Used anywhere?
                std::set<InstLoc *> accesses;
                feo->getAccessSites(-1, accesses, 0);
                // We got some access sites of the eqv obj, fire warnings accordingly.
                for (InstLoc *aloc : accesses) {
                    if (!aloc) {
                        continue;
                    }
                    for (InstLoc *floc : frees) {
                        if (!floc) {
                            continue;
                        }
#ifdef DEBUG_UAF_DETECT
                        dbgs() << "_detectUAFS_ty1(): fireAnUAF, fo: " << (const void*)fo
                        << ", uo: " << (const void*)feo << "\n";
#endif
                        state.fireAnUAF(nullptr, floc, fep, aloc);
                    }
                }
            }
        }

        //Generate and issue Type II UAF warnings: one object escape-fetch first to
        //to the freed object, and then to the used object.
        void _detectUAFS_ty2(GlobalState &state, AliasObject *fo,
                                std::set<InstLoc*> &frees) {
            if (!fo || frees.empty()) {
                return;
            }
            // To deal with this case:
            //(1) Find all objects that can potentially be this freed obj
            //(i.e., backward eqv objects).
            //(2) Find all the used eqv objs of those identified in (1)
            //(i.e., forward eqv objects).
            std::map<AliasObject *, EqvObjPair *> beqv;
            fo->getBackwardEqvObjs(beqv);
            for (auto &e : beqv) {
                AliasObject *beo = e.first;
                assert(beo);
                if (beo == fo) {
                    //In this situation, the Type II case is converted to Type I,
                    //which should have been handled already.
                    continue;
                }
                EqvObjPair *bep = e.second;
                std::map<AliasObject *, EqvObjPair *> feqv;
                beo->getForwardEqvObjs(feqv);
                for (auto &e0 : feqv) {
                    AliasObject *feo = e0.first;
                    assert(feo);
                    EqvObjPair *fep = e0.second;
                    // Current Situation: beo ~> fo, beo ~> feo (~> means "forward equivalence").
                    if (fo == feo) {
                        // This means the F/U objs are the same (say A), and they are all from another
                        // different obj B (via escape/fetch paths). To avoid the unnecessary complexity,
                        // we will not fire such a Type II warning, since a simpler Type I warning
                        // should have already been issued.
                        continue;
                    }
                    // Get the use sites.
                    std::set<InstLoc *> accesses;
                    feo->getAccessSites(-1, accesses, 0);
                    for (InstLoc *aloc : accesses) {
                        if (!aloc) {
                            continue;
                        }
                        for (InstLoc *floc : frees) {
                            if (!floc) {
                                continue;
                            }
#ifdef DEBUG_UAF_DETECT
                            dbgs() << "_detectUAFS_ty2(): fireAnUAF, fo: " << (const void*)fo
                            << ", uo: " << (const void*)feo << ", ro: " << (const void*)beo
                            << "\n";
#endif
                            state.fireAnUAF(bep, floc, fep, aloc);
                        }
                    }
                }
            }
            return;
        }
    
    public:
        void detectUAFs(GlobalState &state) {
            for (AliasObject *fo : state.freedObjs) {
                if (!fo) {
                    continue;
                }
                std::set<InstLoc*> frees;
                fo->getFreeSites(frees);
                //First try to detect the Type I UAFs which is simpler.
#ifdef DEBUG_UAF_DETECT
                dbgs() << "-- detectUAFs(): _detectUAFS_ty1() for fo: "
                << (const void*)fo << "\n";
#endif
                _detectUAFS_ty1(state, fo, frees);
                if (fo->isDummy()) {
                    //If the freed is a placeholder dummy object, we also need
                    //to consider the Type II UAF cases.
#ifdef DEBUG_UAF_DETECT
                    dbgs() << "-- detectUAFs(): _detectUAFS_ty2() for fo: "
                    << (const void*)fo << "\n";
#endif
                    _detectUAFS_ty2(state, fo, frees);
                }
            }
        }

        void addAllVisitorAnalysis(GlobalState &targetState,
                                   Function *toAnalyze,
                                   CallContext *ctx,
                                   std::vector<VisitorCallback*> *allCallbacks,
                                   bool addCallbackPass = true) {

            // This function adds all analysis that need to be run by the global visitor.
            // it adds analysis in the correct order, i.e the order in which they need to be
            // run.

            VisitorCallback *currVisCallback = new AliasAnalysisVisitor(targetState, toAnalyze, ctx);
            //first add AliasAnalysis, this is the main analysis needed by everyone.
            allCallbacks->push_back(currVisCallback);

            //add other analyses that rely on the previous basic analyses.
            //add path analysis.
            currVisCallback = new PathAnalysisVisitor(targetState, toAnalyze, ctx);
            allCallbacks->push_back(currVisCallback);

            //add lockset analysis
            currVisCallback = new LocksetAnalysisVisitor(targetState, toAnalyze, ctx);
            allCallbacks->push_back(currVisCallback);

            //add trait analysis
            currVisCallback = new TraitAnalysisVisitor(targetState, toAnalyze, ctx);
            allCallbacks->push_back(currVisCallback);

            //add callback analysis
            if (addCallbackPass) {
                currVisCallback = new CallbackAnalysisVisitor(targetState, toAnalyze, ctx);
                allCallbacks->push_back(currVisCallback);
            }
        }

        void getAnalysisUsage(AnalysisUsage &AU) const override {
            AU.setPreservesAll();
            AU.addRequired<CallGraphWrapperPass>();
            AU.addRequired<LoopInfoWrapperPass>();
        }

    private:

        void printGVInfo(GlobalVariable &gv) {
            gv.print(dbgs());
            dbgs() << " NUM USES:" << gv.getNumUses() << ", TYPE:";
            gv.getType()->print(dbgs());
            //op1->print(dbgs());
            dbgs() << "\n";

            dbgs() << "For:";
            dbgs() << InstructionUtils::getValueStr(&gv) << ":";
            dbgs() << " of type (" << gv.getType()->getContainedType(0)->isStructTy() << ","
                   << gv.getType()->isPointerTy() << "," << gv.getType()->isArrayTy() << "):";
            gv.getType()->print(dbgs());
            dbgs() << ":";
            if(gv.hasInitializer()) {
                Constant *initializationConst = gv.getInitializer();
                initializationConst->getType()->print(dbgs());
                dbgs() << ", Struct Type:" << initializationConst->getType()->isStructTy();
                if(initializationConst->getType()->isStructTy() &&
                        !initializationConst->isZeroValue()) {
                    ConstantStruct *constantSt = dyn_cast<ConstantStruct>(initializationConst);
                    dbgs() << " Num fields:" << constantSt->getNumOperands() << "\n";
                    for (int i = 0; i < constantSt->getNumOperands(); i++) {
                        dbgs() << "Operand (" << i + 1 << ") :";
                        Function *couldBeFunc = dyn_cast<Function>(constantSt->getOperand(i));
                        dbgs() << "Is Function:" << (couldBeFunc != nullptr) << "\n";
                        if(!couldBeFunc)
                            constantSt->getOperand(i)->print(dbgs());
                        dbgs() << "\n";
                    }
                }
                dbgs() << "\n";
            } else {
                dbgs() << "No initializer\n";
            }
        }

        void setupGlobals(Module &m) {
            /***
             * Set up global variables.
             */
            // map that contains global variables to AliasObjects.
            std::map<Value*, AliasObject*> globalObjectCache;
            std::vector<llvm::GlobalVariable*> visitorCache;
            visitorCache.clear();
            // first add global functions.
            for(Module::iterator mi = m.begin(), ei = m.end(); mi != ei; mi++) {
                GlobalState::addGlobalFunction(&(*mi), globalObjectCache);
            }
            Module::GlobalListType &currGlobalList = m.getGlobalList();
            for (Module::global_iterator gstart = currGlobalList.begin(), gend = currGlobalList.end(); gstart != gend; gstart++) {
                //We cannot simply ignore the constant global structs (e.g. some "ops" structs are constant, but we still need
                //to know their field function pointers to resolve the indirect call sites involving them).
                /*
                // ignore constant immutable global pointers
                if((*gstart).isConstant()) {
                    continue;
                }
                */
                if (!GlobalState::toCreateObjForGV(&(*gstart))) {
                    continue;
                }
                GlobalState::addGlobalVariable(visitorCache, &(*gstart), globalObjectCache);
#ifdef DEBUG_GLOBAL_VARIABLES
                printGVInfo(*gstart);
#endif
                // sanity
                assert(visitorCache.empty());
            }
            globalObjectCache.clear();
            // OK get loop info of all the functions and store them for future use.
            // get all loop exit basic blocks.
            for(Module::iterator mi = m.begin(), ei = m.end(); mi != ei; mi++) {
                Function &currFunction = *mi;
                if(!currFunction.isDeclaration()) {
                    LoopInfoWrapperPass &p = getAnalysis<LoopInfoWrapperPass>(currFunction);
                    LoopInfo &funcLoopInfo = p.getLoopInfo();
                    SmallVector<BasicBlock *, 1000> allExitBBs;
                    allExitBBs.clear();
                    for (auto a:funcLoopInfo) {
                        a->getExitingBlocks(allExitBBs);
                        GlobalState::addLoopExitBlocks(&currFunction, allExitBBs);
                        allExitBBs.clear();
                    }
                }
            }
        }

        //Set up the arg pto records for the callback functions (e.g., workqueue funcs)
        void setupCallbackArgs(GlobalState &targetState, CallContext *ctx, Function *func,
                               int f_cls, CallBackDir *cbd)
        {
            if (!func || !cbd || cbd->dir.empty()) {
                return;
            }
            Instruction *ei = ctx->callSites->at(0);
            InstLoc *loc = InstLoc::getLoc(ei,ctx);
            assert(loc);
            std::map<Value*, std::set<PointerPointsTo*>*> *pMap =
            targetState.getPointsToInfo(ctx);
            long lid = 0;
            for (auto &edir : cbd->dir) {
                CallBackInfo *cbi = edir.second;
                if (!cbi) continue;
                for (auto &e : cbi->arg_ptos) {
                    int no = e.first;
                    if (no < 0 || no >= func->arg_size() || e.second.empty()) {
                        continue;
                    }
                    Value *arg = func->getArg(no);
                    if (!arg) continue;
                    InstLoc *locA = InstLoc::getLoc(arg,ctx,true);
                    assert(locA);
                    // The pto records in "aptos" only have the basic obj|field
                    // info, we also need to set up the pointer variable and the
                    // propagating insts.
                    for (PointerPointsTo *pto : e.second) {
                        if (!pto || !pto->targetObject) {
                            continue;
                        }
                        // Update the pto map.
                        if (pMap->find(arg) == pMap->end()) {
                            (*pMap)[arg] = new std::set<PointerPointsTo *>();
                        }
                        // De-duplication.
                        auto it = std::find_if((*pMap)[arg]->begin(), (*pMap)[arg]->end(),
                                               [pto](PointerPointsTo *p) {
                                                   return pto->pointsToSameObject(p);
                                               });
                        if (it == (*pMap)[arg]->end()) {
                            // Append a loadTag to track this pto, so that we can map
                            // the object used in callback to the related cbi.
                            pto->loadTag.push_back(new TypeField(locA,lid++,nullptr));
                            (*pMap)[arg]->insert(pto);
                        } else {
                            // Duplicated obj|fid, but we still want to append the
                            // loadTag (same id as that duplicated one in the map) to
                            // this pto in cbi, so that we can correctly identify all
                            // the related cbis to a certain object access in the callback
                            // entry later.
                            if (!(*it)->loadTag.empty()) {
                                long id = (*it)->loadTag[0]->fid;
                                pto->loadTag.push_back(new TypeField(locA,id,nullptr));
                            }
                            continue;
                        }
                        //Append some additional info to the inserted ptos.
                        pto->targetPointer = arg;
                        pto->addProp(loc);
                        // Update the records on the object side.
                        pto->targetObject->addPointerPointsTo(pto);
                    }
                }
            }
        }

        void setupFunctionArgs(FuncInf *fi, GlobalState &targetState, CallContext *ctx) {
            if (!fi || !fi->func || !ctx) {
                dbgs() << "!!! setupFunctionArgs(): (!fi || !fi->func || !ctx)\n";
                return;
            }
            // arguments which are tainted and passed by user
            std::set<unsigned long> taintedArgs;
            // arguments which contain tainted data
            std::set<unsigned long> taintedArgData;
            // arguments which are pointer args
            std::set<unsigned long> pointerArgs;
            bool is_handled = false;
            if(fi->ty == IOCTL_HDR) {
                // last argument is the user pointer.
                taintedArgs.insert(fi->func->arg_size() - 1);
                // first argument is the file pointer
                pointerArgs.insert(0);
                is_handled = true;
            }
            //hz: We want to set all global variables as taint source,
            //for ioctl() in driver code, the FILE pointer should also
            //be regarded as a global variable.
            if(fi->ty == MY_IOCTL) {
                //Any user arg indices?
                if (fi->user_args.size() > 0) {
                    for (int i : fi->user_args) {
                        taintedArgs.insert(i);
                    }
                }else {
                    //by default the last argument is the user pointer.
                    taintedArgs.insert(fi->func->arg_size() - 1);
                }
                is_handled = true;
            }
            if(fi->ty == READ_HDR || fi->ty == WRITE_HDR) {
                taintedArgs.insert(1);
                //taintedArgs.insert(2);
                //hz: for now we don't add the args to the "pointerArgs" and create the Arg objects for them, because later in the analysis
                //we will create the objs on demand.
                //pointerArgs.insert(0);
                //pointerArgs.insert(3);
                is_handled = true;
            }
            if(fi->ty == V4L2_IOCTL_FUNC) {
                taintedArgData.insert(fi->func->arg_size() - 1);
                for(unsigned long i=0;i<fi->func->arg_size(); i++) {
                    pointerArgs.insert(i);
                }
                is_handled = true;
            }
            if(fi->ty == DEVATTR_SHOW) {
                for(unsigned long i=0;i<fi->func->arg_size(); i++) {
                    pointerArgs.insert(i);
                }
                is_handled = true;
            }
            if(fi->ty == DEVATTR_STORE) {
                if(fi->func->arg_size() == 3) {
                    // this is driver attribute
                    taintedArgData.insert(1);
                } else {
                    // this is device attribute
                    taintedArgData.insert(2);
                }
                /*
                for (unsigned long i = 0; i < fi->func->arg_size() - 1; i++) {
                    pointerArgs.insert(i);
                }
                */
                is_handled = true;
            }
            if(fi->ty == NETDEV_IOCTL) {
                taintedArgData.insert(1);
                for(unsigned long i=0;i<fi->func->arg_size()-1; i++) {
                    pointerArgs.insert(i);
                }
                is_handled = true;
            }
            //hz: the function doesn't have arguments. This is created for test purposes.
            if(fi->ty == NULL_ARG) {
                is_handled = true;
            }
            if(!is_handled) {
                dbgs() << "Invalid Function Type:" << fi->ty << "\n";
                dbgs() << "Errorring out\n";
            }
            assert(is_handled);


            std::map<Value*, std::set<PointerPointsTo*>*> *currPointsTo =
            targetState.getPointsToInfo(ctx);
            //Create the InstLoc for the function entry.
            Instruction *ei = fi->func->getEntryBlock().getFirstNonPHIOrDbg();
            InstLoc *loc = InstLoc::getLoc(ei,ctx);
            assert(loc);
            unsigned long arg_no=0;
            for(Function::arg_iterator arg_begin = fi->func->arg_begin(), arg_end = fi->func->arg_end(); arg_begin != arg_end; arg_begin++) {
                Argument *currArgVal = &(*arg_begin);
                if (taintedArgs.find(arg_no) != taintedArgs.end()) {
                    //hz: Add a taint tag indicating that the taint is from user-provided arg, instead of global states.
                    //This tag represents the "arg", at the function entry its point-to object hasn't been created yet, 
                    //so no "pobjs" for the tag.
                    TaintTag *currTag = new TaintTag(0,currArgVal,false);
                    TaintFlag *currFlag = new TaintFlag(loc, true, currTag);
                    std::set<TaintFlag*> *currTaintInfo = new std::set<TaintFlag*>();
                    currTaintInfo->insert(currFlag);
                    TaintUtils::updateTaintInfo(targetState, ctx, currArgVal, currTaintInfo);
                }
                if (pointerArgs.find(arg_no) != pointerArgs.end()) {
                    AliasObject *obj = new FunctionArgument(InstLoc::getLoc(currArgVal, ctx),
                                                            currArgVal->getType());
                    //Record the pto in the global state.
                    if (currPointsTo) {
                        PointerPointsTo *pto = new PointerPointsTo(currArgVal,obj,0,loc,false);
                        if (currPointsTo->find(currArgVal) == currPointsTo->end()) {
                            (*currPointsTo)[currArgVal] = new std::set<PointerPointsTo*>();
                        }
                        (*currPointsTo)[currArgVal]->insert(pto);
                        //Update the records on the object side.
                        obj->addPointerPointsTo(pto);
                    }
                    if(taintedArgData.find(arg_no) != taintedArgData.end()) {
                        //In this case the arg obj should be treated as a user-initiated taint source.
                        obj->setAsTaintSrc(loc,false);
                    }
                } else {
                    assert(taintedArgData.find(arg_no) == taintedArgData.end());
                }
                arg_no++;
            }
        }

        //hz: try to set all global variables as taint source.
        void addGlobalTaintSource(GlobalState &targetState) {
            //Type of globalVariables: std::map<Value *, std::set<PointerPointsTo*>*>
            for (auto const &it : GlobalState::globalVariables) {
                Value *v = it.first;
                std::set<PointerPointsTo*> *ps = it.second;
                if (!v || !ps || ps->empty()) {
                    continue;
                }
                GlobalVariable *gv = dyn_cast<GlobalVariable>(v);
                //Exclude the constants which cannot be modified.
                if (gv && gv->isConstant()) {
                    continue;
                }
                //Don't set as taint source for several object types, e.g. function.
                if (v->getType() && v->getType()->isPointerTy()) {
                    Type *ty = v->getType()->getPointerElementType();
                    //Exclude certain types, e.g. function.
                    if (ty->isFunctionTy() || ty->isLabelTy() || ty->isMetadataTy()) {
                        continue;
                    }
                }
#ifdef DEBUG_GLOBAL_TAINT
                dbgs() << "addGlobalTaintSource(): Set the glob var as taint source: " << InstructionUtils::getValueStr(v) << "\n";
#endif
                InstLoc *loc = InstLoc::getLoc(v,nullptr);
                assert(loc);
                for(auto const &p : *ps){
                    if (!p->targetObject) {
                        continue;
                    }
                    //Exclude the const object.
                    if (p->targetObject->is_const) {
                        continue;
                    }
                    p->targetObject->setAsTaintSrc(loc,true);
#ifdef DEBUG_GLOBAL_TAINT
                    dbgs() << "addGlobalTaintSource(): Set the alias obj as taint source:\n";
                    dbgs() << "Object Type: " << InstructionUtils::getTypeName(p->targetObject->targetType) << "\n";
                    dbgs() << " Object Ptr: " << InstructionUtils::getValueStr(p->targetObject->getObjectPtr()) << "\n";
#endif
                }
            }
        }

    };


    char SAAPass::ID = 0;
    static RegisterPass<SAAPass> x("dr_checker", "Soundy Driver Checker", false, true);
}

