//Defines the classes that anstract the condition set/check traits (e.g., patterns).
#ifndef PROJECT_TRAIT_H
#define PROJECT_TRAIT_H

#include <set>
#include <string>
#include <vector>
#include <map>
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "../../Utils/include/Constraint.h"

using namespace llvm;

namespace DRCHECKER {

    //Abstarcts a condition check (e.g., i == 0, i > 1, etc.).
    class TraitCheck {
    public:
        //Define the check types.
        /////////////////////////////////////////////////
        static const int PT_DEF = 0;
        static const int PT_EQ = 1; //e.g., i == N
        static const int PT_NE = 2; //e.g., i != N
        static const int PT_LT = 3; //e.g., i < N
        static const int PT_LE = 4; //e.g., i <= N
        static const int PT_GT = 5; //e.g., i > N
        static const int PT_GE = 6; //e.g., i >= N
        static const int PT_SWITCH = 7; //e.g., switch (i)
        /////////////////////////////////////////////////
        //Define the type of another entity in the comparison.
        /////////////////////////////////////////////////
        static const int ET_DEF = 0;
        static const int ET_VAR = 1; //A variable, e.g., i
        static const int ET_CONST = 2; //A constant, e.g., N
        static const int ET_EXP = 3; //An expression, e.g., i + N
        static const int ET_CONST_SET = 4; //A set of constants, for "switch".
        static const int ET_CONST_BM = 5; //A bit-masked constant, e.g., only 1 bit checked.
        /////////////////////////////////////////////////
        //comparison pattern
        int pat;
        //The type of the other entity in the comparison.
        int ty;
        //The value of the other entity.
        typedef struct VAL_BM {
            uint64_t mask;
            unsigned width;
            int n;
        } VAL_BM; //bit masked constant value.
        typedef union {
            int n;
            VAL_BM *n_bm;
            Value *v;
            std::vector<int64_t> *cset;
        } VAL;
        VAL val;
        //The directory to hold all available TraitCheck, ty -> val -> TraitCheck*
        static std::map<int, std::map<void*,std::set<TraitCheck*>>> dir;
        static TraitCheck *getTraitCheck(int pat, int ty, VAL val);
        //Convert a LLVM cmp predicate to a TraitCheck pattern. 
        static int getTCPattern(CmpInst::Predicate &pred, bool reverse = false);
        //Print the info of this TraitSet.
        void print(raw_ostream &O, bool lbreak = true) {
            O << "pat: " << pat << ", ty: " << ty << ", val: " << val.n << "|"
            << (const void*)val.v;
            if (ty == ET_CONST_SET && val.cset) {
                O << ", cset: ";
                for (auto &e : *val.cset) {
                    O << e << "|";
                }
            }
            if (ty == ET_CONST_BM && val.n_bm) {
                O << ", bitmask: " << (const void*)(val.n_bm->mask) << ", width: "
                << val.n_bm->width << ", n: " << val.n_bm->n;
            }
            if (lbreak)
                O << "\n";
        }
        //Return a z3 expr encoding the constraint of satisfying a desired branch of this
        //TraitCheck, we will use a trivial z3 variable "v" created in the default global
        //z3 context to represent the variable in comparison in the conditional.
        expr getZ3Expr4Branch(unsigned dst, int &ec);
        //Return true if this is a bit-masked check and the mask bits are continuous,
        //also calculate the start bits and #bits masked.
        bool isContMasked(unsigned &st, unsigned &len);
        //For the cmp pattern of this TraitCheck, "ns" is the variable value (left side),
        //"nc" is the cmp-against constant (right side), "true_br" indicates whether
        //the true branch is expected to be taken.
        //Return true if the desired branch cannot be taken (check failed). 
        bool constantCheckFail(int ns, int nc, bool true_br);
    private:
        TraitCheck(int pat, int ty, VAL val) {
            this->pat = pat;
            this->ty = ty;
            this->val = val;
        };
    public:
        TraitCheck(TraitCheck const&) = delete;
        void operator=(TraitCheck const&) = delete;
    };

    //Abstract an update pattern of a variable (e.g., constant assignment, self ++).
    class TraitSet {
    public:
        //Define update types.
        /////////////////////////////////////////////////
        static const int PT_DEF = 0;
        static const int PT_CONST = 1; //constant assignment
        static const int PT_ADJ = 2; //adjust the existing value (e.g., i++)
        static const int PT_VAR = 3; //variable assignment that we cannot trace back.
        static const int PT_CONST_UNK = 4; //constant assignment w/ an unknown value.
        /////////////////////////////////////////////////
        //Define the operators used in the pattern (e.g., for PT_ADJ).
        /////////////////////////////////////////////////
        static const int OP_DEF = 0;
        static const int OP_ADD = 1;
        static const int OP_SUB = 2;
        static const int OP_MUL = 3;
        static const int OP_DIV = 4;
        static const int OP_MOD = 5;
        static const int OP_AND = 6;
        static const int OP_OR = 7;
        static const int OP_XOR = 8;
        static const int OP_SHL = 9;
        static const int OP_SHR = 10;
        /////////////////////////////////////////////////
        //update pattern
        int pat;
        //constant involved in this update (signed).
        int n;
        //operator used in this update.
        int op;
        //The directory to hold all available TraitSet, pattern -> n -> TraitSet*
        static std::map<int,std::map<int,std::set<TraitSet*>>> dir;
        static TraitSet *getTraitSet(int pat, int n = 0, int op = OP_DEF);
        //Return true if this TraitSet can kill the "dst" branch of the provided TraitCheck "tc".
        //E.g., assume "dst" is 0 (true branch) and "tc" is "a == 1", then if this TraitSet is
        //"a = 0", it will be a killer.  
        bool kill(TraitCheck *tc, unsigned dst);
        //Print the info of this TraitSet.
        void print(raw_ostream &O, bool lbreak = true) {
            O << "pat: " << this->pat << ", op: " << this->op << ", n: " << this->n;
            if (lbreak)
                O << "\n";
        }
        // Return true if this TraitSet can completely re-write the specified
        // bit range in the variable to a fixed value, if so, the value will
        // be stored to "res".
        bool writeBitRange(unsigned st, unsigned len, unsigned &res);
    private:
        TraitSet(int pat, int n, int op) {
            this->pat = pat;
            this->n = n;
            this->op = op;
        }
        TraitSet(): TraitSet(PT_DEF, 0, OP_DEF) {}
    public:
        //Design pattern stuff according to below link:
        //https://stackoverflow.com/questions/1008019/c-singleton-design-pattern
        TraitSet(TraitSet const&) = delete;
        void operator=(TraitSet const&) = delete;
    };
}
#endif