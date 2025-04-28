#ifndef PROJECT_LOCKINFO_H
#define PROJECT_LOCKINFO_H

#include "CFGUtils.h"

using namespace z3;

namespace DRCHECKER {

    // This class abstracts an InstLoc performing lock/unlock actions. 
    class LockInfo {
    public:
        //Where the lock/unlock happens.. 
        InstLoc *loc;
        //Whether it's a lock or unlock.
        bool lock;
        //The function used to perform the lock/unlock, e.g., mutex_lock().
        std::string fn;
        //The lock objects...
        std::set<PointerPointsTo*> objs;
        //Its paired lock/unlock info entries, note that one lock is not necessarily paired with only one unlock,
        //(e.g., multiple unlocks can be put in different exit paths within one function, another special case is
        //a same lock/unlock invacation can result in multiple invocation IRs due to compiler's decision.)
        std::set<LockInfo*> pairs;

        LockInfo(InstLoc *loc, bool lock, std::set<PointerPointsTo*> *pobjs, std::string *pfn) {
            this->loc = loc;
            this->lock = lock;
            if (pobjs) {
                this->objs = *pobjs;
            }
            if (pfn) {
                this->fn = *pfn;
            }
        }

        //Decide whether this lock has the same lock objects as another one.
        //One lock entry may have multiple lock objs (e.g., a set), to be conservative, as long as the two
        //sets have a non-null intersection, return true.
        //TODO: consider whether this is a good decision.
        //NOTE: in this function we don't consider eqv objects, we consider it in another version of this function in ModuleState.h
        int sameLockObjs(LockInfo *other) {
            if (!other) {
                return 0;
            }
            if (this->objs.empty() && other->objs.empty()) {
                //This suggests that the lock/unlock don't operate on an object,
                //instead they are globally effective (e.g., console_lock()
                //and console_unlock()).
                return 1;
            }
            for (PointerPointsTo *pto : this->objs) {
                if (!pto) {
                    continue;
                }
                for (PointerPointsTo *t : other->objs) {
                    //TODO: consider matching by eqv objects...
                    if (t && t->pointsToSameObject(pto)) {
                        return 1;
                    }
                }
            }
            return 0;
        }

        //Dump the essential info of this lock entry.
        void print(llvm::raw_ostream &O) {
            O << "LockInfo(" << (const void*)this << ") func: " << this->fn << ", is_lock: " << this->lock << ", loc: ";
            if (this->loc) {
                this->loc->print_light(O,false);
            }
            O << ", objs: ";
            for (PointerPointsTo *pto : this->objs) {
                if (pto) {
                    O << (const void*)(pto->targetObject) << "|" << pto->dstfieldId << " ~ ";
                }
            }
            O << ", paired: ";
            for (LockInfo *p : this->pairs) {
                O << (const void*)p << ", ";
            }
            O << "\n";
        }
    private:
        //
    };
}
#endif
