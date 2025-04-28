//
// Created by machiry on 8/23/16.
//

#ifndef PROJECT_INSTRUCTIONUTILS_H
#define PROJECT_INSTRUCTIONUTILS_H
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/ValueSymbolTable.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/IR/Operator.h"
#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/ModuleSlotTracker.h"
#include <string>
#include <sstream>
#include <chrono>
#include <ctime>
#include <map>

#define TIMING
#define TIMING_GLOB

using namespace llvm;

namespace DRCHECKER {

    extern ModuleSlotTracker *mSlotTracker;
    
    //Encode the information of a field (at a certain bit offset) in a (nested) structure
    class FieldDesc {
        public:
        int bitoff = 0;
        //host_tys and fid: from innermost to outermost.
        std::vector<Type*> tys, host_tys;
        std::vector<unsigned> fid;

        FieldDesc() {
            this->bitoff = 0;
            return;
        }

        FieldDesc(FieldDesc *fd) {
            if (!fd)
                return;
            this->bitoff = fd->bitoff;
            this->tys = fd->tys;
            this->host_tys = fd->host_tys;
            this->fid = fd->fid;
        }

        void print(raw_ostream &OS);

        void print_path(raw_ostream &OS);

        //Whether a certain type is in the "tys" list.
        int findTy(Type *ty, bool wildp = false);

        int findHostTy(Type *ty);

        Type *getOutermostTy();
    };

    class CandStructInf {
        public:
        std::vector<FieldDesc*> *fds;
        std::vector<int> ind;
        float score = .0;
        bool field_name_matched = false;

        bool same(CandStructInf *c) {
            if (!c)
                return false;
            return (this->fds == c->fds && this->ind == c->ind);
        }
    };

    //This is a multi-purpose class to provide some infos.
    class TypeField {
        public:
        TypeField(Type *ty, long fid, void *priv = nullptr, std::set<void*> *ptfs = nullptr, void *v = nullptr) {
            this->ty = ty;
            this->fid = fid;
            this->priv = priv;
            if (ptfs) {
                this->tfs = *ptfs;
            }
            this->v = v;
        }

        TypeField(TypeField *other) {
            if (other) {
                this->ty = other->ty;
                this->fid = other->fid;
                this->priv = other->priv;
                this->tfs = other->tfs;
                this->v = other->v;
            }
        }

        //Constructor wrapper 0: null.
        TypeField(): TypeField(nullptr,0,nullptr,(std::set<void*>*)nullptr,nullptr) {}

        //Constructor wrapper 1: mainly used to hold a load tag (i.e. load src pointer, object and field).
        TypeField(void *loc, long fid, void *obj, long n = 0): 
        TypeField(nullptr,fid,obj,(std::set<void*>*)nullptr,(void*)loc) {
            this -> n = n;
        }
        
        bool is_same_ty(TypeField *tf);

        //As long as two load tags have the same "v" (i.e. load src pointer), we say they are similar.
        bool isSimilarLoadTag(TypeField *tf) {
            if (!tf) {
                return false;
            }
            return (this->v == tf->v);
        }

        bool isSameLoadTag(TypeField *tf) {
            if (!tf) {
                return false;
            }
            return (this->v == tf->v && this->fid == tf->fid);
        }
 
        Type *ty = nullptr;
        long fid = 0;
        //Private field that can be customized (e.g., can be an pointer to a concrete AliasObject that is of type "ty")
        void *priv = nullptr;
        //Used to hold a TaintFlag* in some cases.
        std::set<void*> tfs;
        //This can be customized to store anything desirable.
        void *v = nullptr;
        //A priv value.
        long n = 0;
    };

    class InstructionUtils {
        public:
        /***
         *  Is any of the operands to the instruction is a pointer?
         * @param I  Instruction to be checked.
         * @return  true/false
         */
        static bool isPointerInstruction(Instruction *I);

        /***
         *  Get the name of the provided instruction.
         * @param I instruction whose name needs to be fetched.
         * @return string representing the instruction name.
         */
        static std::string getInstructionName(Instruction *I);

        /***
         * Get the name of the provided value operand.
         * @param v The value operand whose name needs to be fetched.
         * @return string representing name of the provided value.
         */
        static std::string getValueName(Value *v);

        /***
         *  Method to convert string to be json friendly.
         *  Copied from: https://stackoverflow.com/questions/7724448/simple-json-string-escape-for-c
         * @param input input string
         * @return converted string.
         */
        static std::string escapeJsonString(const std::string& input);

        /***
         * Method to convert the provided value to escaped json string.
         *
         * @param currInstr Value object which needs to be converted to json string.
         * @return Converted string.
         */
        static std::string escapeValueString(Value *currInstr);

        /***
         * Get the instruction line number corresponding to the provided instruction.
         * @param I Instruction whose line number needs to be fetched.
         * @return Line number.
         */
        static int getInstrLineNumber(Instruction *I);

        /***
         * Get the correct Debug Location (handles in lineing) for the provided instruction.
         *
         * @param I instruction whose correct debug location needs to be fetched.
         * @return DILocation correct debug location corresponding to the provided instruction.
         */
        static DILocation* getCorrectInstrLocation(Instruction *I);
        
        //hz: my experimental replacement of the above.
        static int getCorrectInstLoc(Instruction *I, std::vector<DILocation*> &res);

        //Get all the host function names of a certain inst, including those inlined ones
        //since we get the result from querying the DILocation dbg info.
        static int getHostFuncsFromDLoc(Instruction *I, std::vector<std::string> &res);

        //Print the instruction with detailed src level debug info (e.g. file, line number).
        static void printInst(Instruction *I, raw_ostream &OS);

        //Print the same information as "printInst", but organize these infos in Json format (i.e. key-value pairs).
        static void printInstJson(Instruction *I, raw_ostream &OS);

        //If the BB has a name then return it, otherwise return its numeric ID as shown in ".ll".
        static std::string& getBBStrID(BasicBlock*);

        //If the BB has a name then return it, otherwise return its order within its parent function BB iteration.
        static std::string& getBBStrID_No(BasicBlock*);
        static std::string& getInstStrID_No(Instruction*);

        //Set up a cache for the expensive "print" operation for llvm::Value.
        static std::string& getValueStr(Value *v);

        //Set up a cache for the expensive "print" operation for llvm::Type.
        static std::string& getTypeStr(Type*);

        static bool isScalar(Value*);

        static bool getConstantValue(Constant *C, int64_t *sres, uint64_t *ures);

        static Value *stripAllCasts(Value*,bool);

        static Value *stripAllSoleTrans(Value *v);

        static bool isSelfStore(StoreInst *si);

        static void stripFuncNameSuffix(std::string *fn);

        static std::string getCalleeName(CallInst*,bool);

        static bool ptr_sub_type(Type*,Type*);

        static int getPtrLayer(Type *ty, Type **bty);

        static bool same_types(Type*,Type*,bool = false);

        //Return true if "ty" is a composite type.
        static inline bool isCompTy(Type *ty) {
            return (ty && (ty->isStructTy() || ty->isArrayTy() || ty->isVectorTy()));
        }

        //Return true if "ty" is a seq type.
        //If "ety" or "len" is provided, also return the element type and length of the seq.
        //Ret: 1: array, 2: vec, 0: not a seq ty.
        static inline int isSeqTy(Type *ty, Type **ety = nullptr, uint64_t *len = nullptr) {
            if (!ty) {
                return 0;
            } else if (ty->isArrayTy()) {
                if (ety) {
                    *ety = ty->getArrayElementType();
                }
                if (len) {
                    *len = ty->getArrayNumElements();
                }
                return 1;
            } else if (ty->isVectorTy()) {
                if (ety) {
                    *ety = dyn_cast<VectorType>(ty)->getElementType();
                }
                if (len) {
                    // Note that there are two types of vectors: fixed and scalable,
                    // while "getKnownMinValue()" will return the exact length of the former,
                    // the latter is extendable and thus doesn't have a fixed size, so
                    //"getKnownMinValue" only returns its minimal length.
                    *len = dyn_cast<VectorType>(ty)->getElementCount().getKnownMinValue();
                }
                return 2;
            }
            return 0;
        }

        //Get the "cmd" arg values of the ioctl() that can reach the target "inst" under the context "ctx".
        static std::set<uint64_t> *getCmdValues(std::vector<Instruction*> *ctx, Instruction* inst, 
                                                std::map<BasicBlock*,std::set<uint64_t>> *switchMap);

        static std::map<ConstantAggregate*,std::set<long>> *getUsesInGlobalConstStruct(Value *v);

        static std::map<Type*,std::set<long>> *getUsesInStruct(Value *v);

        //Create a new GEP from an existing one, using only the first few indices.
        static GetElementPtrInst *createSubGEP(GEPOperator*,unsigned);

        static bool isAsanInst(Instruction *inst);

        static Instruction *isAsanReportBB(BasicBlock *bb);

        static bool isPotentialAsanInst(Instruction *inst);

        static FieldDesc *getHeadFieldDesc(Type *ty);

        static void getHeadTys(Type *ty, std::set<Type*> &rs);

        static Type *getHeadTy(Type *ty);

        static std::vector<FieldDesc*> *getCompTyDesc(DataLayout *dl, Type *ty);

        static bool isTyUsedByFunc(Type *ty, Function *func);

        static bool isIndexValid(Type *ty, long fid);

        static Type *getTypeAtIndex(Type *ty, long fid, int *err = nullptr);

        //Given a type's type desc vector, locate the first desc node for a specified field "fid",
        //returning the index of this desc node within the vector.
        static int locateFieldInTyDesc(std::vector<FieldDesc*> *tydesc, unsigned fid);

        //Given a type's type desc vector, locate the first desc node for a specified bit offset,
        //returning the index of this desc node within the vector.
        static int locateBitsoffInTyDesc(std::vector<FieldDesc*> *tydesc, int boff);

        static std::string getStFieldName(Module *mod, StructType *ty, unsigned fid);

        //This holds all metadata nodes in the module.
        static DenseMap<MDNode*, unsigned> mdnCache;

        //This holds the name->DIC mapping, the name is the struct name like "file" (no struct. prefix and no numeric suffix).
        static std::map<std::string,DICompositeType*> dicMap;

        static int getAllMDNodes(Module *mod);

        static int setupDicMap(Module *mod);

        static bool isPrimitivePtr(Type *ty, int bit = 0);

        static bool isPrimitiveTy(Type *ty, int bit = 0);

        static bool isNullCompPtr(Type *ty);

        static bool isNullCompTy(Type *ty);

        static Type *getStTypeByName(Module *mod, std::string &n);

        static bool isOpaqueSt(Type *ty);

        static long calcGEPTotalOffsetInBits(GEPOperator *gep, DataLayout *dl, int *rc = nullptr);

        static std::string& getTypeName(Type *ty);

        static void trim_num_suffix(std::string *s);

        static std::string trim_struct_name(std::string &s);

        static std::chrono::time_point<std::chrono::system_clock> getCurTime(raw_ostream *OS = nullptr);

        static double getTimeDuration(std::chrono::time_point<std::chrono::system_clock> prev, raw_ostream *OS = nullptr);

        static int dumpFuncGraph(Function *f);

        static void printCallingCtx(raw_ostream &O, std::vector<Instruction*> *ctx, bool lbreak = false);
        
        static Type *inferPointeeTy(Value *v);

        static bool isPotentialIndirectCallee(Function *func);

        static void filterPossibleFunctionsByLoc(Instruction *inst, std::set<Function*> &targetFunctions);

        /***
         * Get potential targets of a call instruction from its type information.
         * @param callInst Call instruction whose targets need to be fetched.
         * @param targetFunctions Set to which possible targets should be added.
         * @return true/false depending on targets is non-empty or empty.
         */
        static bool getPossibleFunctionTargets(CallInst &callInst, std::set<Function*> &targetFunctions);

        static bool similarStName(const std::string &s0, const std::string &s1);
        
        static BasicBlock *getSinglePredecessor(BasicBlock *bb);
        
        static Argument *getArg(Function *func, unsigned n);
        
        static int isSimilarLoadTag(std::vector<TypeField*> *t0, std::vector<TypeField*> *t1);

        static int matchLoadTags(std::vector<TypeField*> *t0, std::vector<TypeField*> *t1, int l0 = 0, int l1 = 0);

        //If the type is a node of some recursive data structures, return the type name of the node (e.g., list_head), otherwise empty str.
        static std::string isRecurTy(Type *ty);

        //Whether the type is a ptr to a recur type (e.g., list_head*).
        static std::string isRecurPtrTy(Type *ty);

        static bool seq_compatiable(StructType *ty, Type **bty, int *sz);

        static void probeFilePrivTy(Value *p, std::set<Type*> &retSet);

        //Decide whether "ty" contains another type named "tyName" (e.g., field of a struct).
        //Note that only a StructType has a name, so the passed-in "ty" must be composite.
        static bool containTy(Type *ty, const std::string &tyName);

        //Return true if "ty" is the specified type (tyName), or one sub-type
        //(might be multiple layer nest) at index "fid" is.
        static bool isTyAtIndex(Type *ty, long fid, const std::string &tyName);

        //Return true if the type at "fid" is a recursive type.
        static bool isRecurTyAtIndex(Type *ty, long fid);

        //Get all involved values in "v", e.g., if "v" is an inst, get all operands.
        static int getInvolvedValues(Value *v, std::set<Value*> &res, bool inc_const = false);
    };

}
#endif //PROJECT_INSTRUCTIONUTILS_H
