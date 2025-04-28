//
// Created by machiry on 12/3/16.
//

#ifndef PROJECT_CFGUTILS_H
#define PROJECT_CFGUTILS_H
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/SCCIterator.h"
#include "llvm/IR/CFG.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/PostDominators.h"
#include "InstructionUtils.h"

using namespace llvm;
namespace DRCHECKER {

    #define DEBUG_INTER_PROC_POSTDOM
    #define DEBUG_INTER_PROC_DOM

    class CallContext;
    class InstLoc;

    //Class that abstracts the calling context.
    class CallContext {
    public:
        //Sequence format: entry inst in the caller -> callsite in caller -> ...
        std::vector<Instruction*> *callSites;
        //All available calling contexts on file.
        //callSites[0] -> callSites[-1] -> CallContext instances 
        static std::map<Instruction*,std::map<Instruction*,std::set<CallContext*>>> dir;
        //Get an existing context, or create a new one if required.
        static CallContext *getContext(std::vector<Instruction*> *callSites,
                                       bool create = true, bool *created = nullptr);

        //Get a prefixing context of "this", "ci" is the ending index of the prefix.
        CallContext *getPrefix(unsigned ci, bool create = true) {
            //A prefix should also be a valid context, whose length must be odd.
            if (ci >= this->callSites->size() || ci % 2) {
                dbgs() << "!!! getPrefix(): Invalid prefix length\n";
                return nullptr;         
            }
            if (ci == this->callSites->size() - 1) {
                //Trivial case.
                return this;
            }
            std::vector<Instruction *> newCtx(this->callSites->begin(),
                                              this->callSites->begin() + ci + 1);
            return CallContext::getContext(&newCtx, create);
        }

        CallContext *getParentContext(bool create = true) {
            if (!this->callSites || this->callSites->size() < 3) {
                return nullptr;
            }
            return this->getPrefix(this->callSites->size() - 3, create);
        }

        //"ci" is a call site under "ctx", this function tries to get all CallContexts
        //for the target(s) of that call site.
        static int getCalleeCtx(CallContext *ctx, CallInst &ci, std::set<CallContext*> &res) {
            if (!ctx || !ctx->callSites || ctx->callSites->empty()) {
                return -1;
            }
            Function *callee = ci.getCalledFunction();
            if (callee) {
                if (callee->isDeclaration()) {
                    //No function body presents, impossible to get the context then.
                    return -1;
                }
                Instruction *calleeEntry = callee->getEntryBlock().getFirstNonPHIOrDbg();
                if (!calleeEntry) {
                    return -1;
                }
                std::vector<Instruction*> calleeCtx(ctx->callSites->begin(),
                                                    ctx->callSites->end());
                calleeCtx.push_back(&ci);
                calleeCtx.push_back(calleeEntry);
                //This function will not create new context, only query.
                CallContext *cctx = CallContext::getContext(&calleeCtx, false);
                if (!cctx) {
                    return -1;
                }
                res.insert(cctx);
                return 0;
            }
            //Ok, this should be a indirect call, we need to iterate through the directory
            //and do the match.
            for (auto &e0 : CallContext::dir[ctx->callSites->at(0)]) {
                for (CallContext *tctx : e0.second) {
                    //Quick filtering.
                    if (!tctx->callSites ||
                        tctx->callSites->size() != ctx->callSites->size() + 2 ||
                        tctx->callSites->at(ctx->callSites->size()) != &ci) {
                            continue;
                    }
                    //Inst by inst matching.
                    unsigned i = 0;
                    for (; i < ctx->callSites->size(); ++i) {
                        if (tctx->callSites->at(i) != ctx->callSites->at(i)) {
                            break;
                        }
                    }
                    if (i >= ctx->callSites->size()) {
                        res.insert(tctx);
                    }
                }
            }
            return 0;
        }

        //Return true if this calling context matches the calling
        //sequence in "callSites".
        bool same(std::vector<Instruction*> *callSites) {
            if (!callSites || callSites->empty()) {
                return false;
            }
            return (*(this->callSites) == *callSites);
        }

        //Whether this ctx prefixes another.
        //Identical ctx: return 0, prefix: return the 1st index after the prefix, otherwise -1.
        int isPrefix(CallContext *other) {
            if (!other) {
                return -1;
            }
            if (other->callSites->size() < this->callSites->size()) {
                return -1;
            }
            for (unsigned i = 0; i < this->callSites->size(); ++i) {
                if (other->callSites->at(i) != this->callSites->at(i)) {
                    return -1;
                }
            }
            if (this->callSites->size() == other->callSites->size()) {
                //Identical contexts.
                return 0;
            }
            return this->callSites->size();
        }

        void print(llvm::raw_ostream &O, bool lbreak = true) {
            InstructionUtils::printCallingCtx(O, this->callSites, lbreak);
        }

        void printJson(llvm::raw_ostream &O) {
            O << "\"context\":[";
            bool putComma = false;
            if (this->callSites) {
                for (Instruction *currCallSite : *(this->callSites)) {
                    if (putComma) {
                        O << ",";
                    }
                    O << "{";
                    InstructionUtils::printInstJson(currCallSite, O);
                    O << "}\n";
                    putComma = true;
                }
            }
            O << "\n]";
        }

        bool empty() {
            return ((!this->callSites) || this->callSites->empty());
        }
    private:
        CallContext(std::vector<Instruction*> *callSites) {
            //We don't know whether the passed-in callSites will last
            //(e.g., maybe it's stack based), so to be safe we allocate
            //a new vector.
            assert(callSites);
            this->callSites = new std::vector<Instruction*>(callSites->begin(),
                                                            callSites->end());
        }
    public:
        CallContext(CallContext const&) = delete;
        void operator=(CallContext const&) = delete;
    };

    // This encodes the information to locate an instruction within a certain call context,
    // it also provides some utilities like reachability test w/ another instruction.
    class InstLoc {
    public:
        //The llvm inst itself.
        Value *inst;
        //The calling context of this inst.
        CallContext *ctx;
        //All currently available InstLocs..
        static std::map<Value*,std::set<InstLoc*>> dir;
        static InstLoc *getLoc(Value *inst, CallContext *ctx, bool create = true);

        bool hasCtx() {
            return (this->ctx && this->ctx->callSites && !this->ctx->callSites->empty());
        }

        //Return the first inst in the calling context (i.e. the first inst of the top-level entry function).
        Instruction *getEntryInst() {
            if (!this->hasCtx()) {
                return nullptr;
            }
            return this->ctx->callSites->at(0);
        }

        //Whether "this"'s ctx is a prefix of "other"'s.
        //Identical ctx: return 0, prefix: return the 1st index after the prefix, otherwise -1.
        int isCtxPrefix(InstLoc *other) {
            if (!other) {
                return -1;
            }
            if (!other->hasCtx()) {
                return (this->hasCtx() ? -1 : 0);
            }
            return this->ctx->isPrefix(other->ctx);
        }

        Function *getFunc() {
            Instruction *I = dyn_cast<Instruction>(this->inst);
            if (!I || !I->getParent()) {
                return nullptr;
            }
            return I->getFunction();
        }

        Function *getEntryFunc() {
            Instruction *I = this->getEntryInst();
            if (!I || !I->getParent()) {
                return nullptr;
            }
            return I->getFunction();
        }

        void print(raw_ostream &O);

        //One line compact output of this InstLoc.
        void print_light(raw_ostream &O, bool lbreak = true);

        //Return true if this InstLoc post-dominates the "other" InstLoc.
        bool postDom(InstLoc *other, bool is_strict = true);

        //Return true if this InstLoc dominates the "other" InstLoc.
        bool dom(InstLoc *other, bool is_strict = true);
        
        //Return true if this is reachable from the "other" InstLoc, under the presence of the blocking instructions in the "blocklist".
        bool reachable(InstLoc *other, std::set<InstLoc*> *blocklist = nullptr);

        //A wrapper for convenience, decide the relative positioning of two InstLocs.
        bool mreachable(InstLoc *refloc, int pos = 0);
        
        //Decide whether current inst can be reached from (or return to) its one specified upward callsite (denoted by the
        //index "ci" in its calling context), in the presence of the blocking insts in the "blocklist".
        bool chainable(int ci, std::set<InstLoc*> *blocklist, bool callFrom = true);

        //Decide whether "this" can be reached from the entry or can reach the return of its host function 
        //when there exists some blocking nodes.
        bool canReachEnd(std::set<InstLoc*> *blocklist, bool fromEntry = true);

        void getBlockersInCurrFunc(std::set<InstLoc*> *blocklist, std::set<Instruction*> &validBis);
        
        //See BBTraversalHelper::getCriticalBranches for the definition of critical
        //branches, this function gets the critical branches inter-procedurally for
        //this InstLoc.
        void getCriticalBranches(std::map<InstLoc*,unsigned> &res);
    
    private:
        InstLoc(Value *inst, CallContext *ctx) {
            this->inst = inst;
            this->ctx = ctx;
        }

    public:
        InstLoc(InstLoc const&) = delete;
        void operator=(InstLoc const&) = delete;
    };

    extern void printInstlocJson(InstLoc *inst, llvm::raw_ostream &O);

    extern void printInstlocTraceJson(std::vector<InstLoc*> *instTrace, llvm::raw_ostream &O);

    extern void getCtxOfLocTr(const std::vector<InstLoc*> *tr, std::vector<CallContext*> &res);

    extern bool sameLocTr(std::vector<InstLoc*> *tr0, std::vector<InstLoc*> *tr1);
    
    //Get the order of this warning, order can be viewed as the necessary invocation times of entry functions to trigger
    //the bug (e.g. if to trigger this warning we need to first invoke entry function A then B, we say its order is 2, 
    //another example is we may need to first invoke ioctl() w/ cmd 0, then the same ioctl() w/ cmd 1, the order is still
    //2 since we need to invoke an entry function for 2 times).
    extern int getTrOrder(std::vector<InstLoc*> *tr);

    //Decide whether the U site uses a local pointer derived from the A site
    //(e.g., kmalloc()), note that "uloc" encodes the pointer used by the U site,
    //instead of the U site itself.
    extern bool is_loc_a2u(InstLoc *aloc, InstLoc *uloc);

    //Return true if "loc->inst" eventually points to local memory (e.g., a stack based obj).
    //This function can do the inter-procedure tracking.
    extern int is_local_ptr(InstLoc *loc);

    extern int getSrcLoad(InstLoc *loc, std::set<InstLoc*> &res);

    class BBTraversalHelper {
    public:
        /***
         * Get the Strongly connected components(SCC) of the CFG of the provided function in topological order
         * @param currF Function whose SCC visiting order needs to be fetched.
         * @return vector of vector of BasicBlocks.
         *     i.e vector of SCCs
         */
        static std::vector<std::vector<BasicBlock *> *> *getSCCTraversalOrder(Function &currF);

        //print the TraversalOrder to the output stream
        static void printSCCTraversalOrder(std::vector<std::vector<BasicBlock *>*> *order, raw_ostream *OS);

        /***
         * Get number of times all the BBs in the provided strongly connected component need to be analyzed
         * So that all the information is propagated correctly.
         * @param currSCC vector of BBs in the Strongly connected component.
         * @return number of times all the BBs needs to be analyzed to ensure
         * that all the information with in SCC is properly propagated.
         */
        static unsigned long getNumTimesToAnalyze(std::vector<BasicBlock *> *currSCC);

        /***
         * Checks whether a path exists from startInstr to endInstr along provided callSites.
         *
         * @param startInstr src or from instruction from where we need to check for path.
         * @param endInstr dst or to instruction to check for path
         * @param callSites pointer to the vector of callsites through which endInstr is reached from startInstr
         * @return true/false depending on whether a path exists or not.
         */
        static bool isReachable(Instruction *startInstr, Instruction *endInstr, std::vector<Instruction*> *callSites);

        static llvm::DominatorTree *getDomTree(llvm::Function*);

        static void getDominators(llvm::BasicBlock *bb, std::set<llvm::BasicBlock*> &res, bool self = true);

        static void getDominatees(llvm::BasicBlock *bb, std::set<llvm::BasicBlock*> &res, bool self = true);

        //NOTE: as long as we have the post-dom tree, we can invoke its member function "->dominates()" to decide the
        //post-dominance relationship of two Insts:
        //Prototype from the llvm src file:
        /// Return true if \p I1 dominates \p I2. This checks if \p I2 comes before
        /// \p I1 if they belongs to the same basic block.
        /// bool dominates(const Instruction *I1, const Instruction *I2) const;
        static llvm::PostDominatorTree *getPostDomTree(llvm::Function*);

        //We assume src and end are within the same function.
        static bool instPostDom(Instruction *src, Instruction *end, bool is_strict = false);

        //We assume src and end are within the same function.
        static bool instDom(Instruction *src, Instruction *end, bool is_strict = false);

        //Get all dom nodes for all return sites (i.e. in order to return we must pass these nodes).
        static void getDomsForRet(llvm::Function* pfunc, std::set<llvm::BasicBlock*> &ret);

        static void getRetBBs(llvm::Function* pfunc, std::set<llvm::BasicBlock*> &r);
        
        static void getRetInsts(llvm::Function* pfunc, std::set<llvm::Instruction*> &r);

        //The mapping from one BB to all its successors (recursively).
        static std::map<BasicBlock*,std::set<BasicBlock*>> succ_map;

        static void _get_all_successors(BasicBlock *bb, std::set<BasicBlock*> &res);

        static std::set<BasicBlock*> *get_all_successors(BasicBlock *bb);

        //Given a multi-successor BB, we want to know how each of its direct
        //successors is governed by the conditional - some may be only
        //reachable under the branch condition posed, some may not.
        //E.g. 0
        //if (...) {do_sth_1;} do_sth_2;
        //While do_sth_1 is governed by the true branch condition, do_sth_2
        //is not.
        //One direct successor can also be gorverned by multiple branches.
        //E.g. 1
        //switch(...) {
        //    case 0:
        //        do_sth_0;
        //    case 1:
        //        do_sth_1;
        //    default:
        //        break;
        //}
        //Here do_sth_1 is reachable in either branch 0 or 1, but not in
        //"default".
        //Ret:
        //A map: direct succ BB -> set of direct succ BBs that can reach
        //the key BB (e.g., in above e.g, 0, do_sth_1 only has one BB in
        //the value set which is itself).
        static std::map<BasicBlock*,std::set<BasicBlock*>> *getCondCoverMap(
                                                            BasicBlock *bb);
        
        //A critical branch instruction for a given instruction is one whose one specifc
        //direction must be taken in order to reach that given instruction, e.g.,
        //  if (A) stmt_0;
        //  if (B) stmt_1;
        //In this segment, if (B) is critical for stmt_1, but if (A) is not (e.g., both
        //of its directions can reach stmt_1).
        //This function try to find all the critical branch instructions for "inst"
        //within the host function.
        static std::map<llvm::Instruction*, unsigned> *getCriticalBranches(
                                                    llvm::Instruction *inst);

        //Get all paths from path[0] to the function return, record the paths into "res".
        static int getPathsToRet(std::vector<llvm::BasicBlock*> &path,
                                 std::set<std::vector<llvm::BasicBlock*>> &res);

        //Get all the BBs where "v" gets used.
        static void getUseBBs(Value *v, std::set<llvm::BasicBlock*> &res);
    };
}
#endif //PROJECT_CFGUTILS_H
