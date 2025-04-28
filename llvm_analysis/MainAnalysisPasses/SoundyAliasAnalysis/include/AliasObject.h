//
// Created by machiry on 10/24/16.
//

#ifndef PROJECT_ALIASOBJECT_H
#define PROJECT_ALIASOBJECT_H
#include <set>
#include <string>
#include <llvm/Support/Debug.h>
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "TaintInfo.h"
#include "../../Utils/include/CFGUtils.h"
#include "Trait.h"

using namespace llvm;
#ifdef DEBUG
#undef DEBUG
#endif

//hz: some debug output options.
//#define DEBUG_OUTSIDE_OBJ_CREATION
#define ENABLE_SUB_OBJ_CACHE
#define SMART_FUNC_PTR_RESOLVE
#define DEBUG_SMART_FUNCTION_PTR_RESOLVE
#define DEBUG_FETCH_POINTS_TO_OBJECTS
#define DEBUG_CHANGE_HEAPLOCATIONTYPE
#define DEBUG_UPDATE_FIELD_POINT
#define DEBUG_CREATE_DUMMY_OBJ_IF_NULL
#define DEBUG_CREATE_EMB_OBJ
#define DEBUG_CREATE_HOST_OBJ
#define DEBUG_INFER_CONTAINER
#define DEBUG_SPECIAL_FIELD_POINTTO
#define DEBUG_SHARED_OBJ_CACHE
#define DEBUG_OBJ_RESET
#define DEBUG_OBJ_COPY
#define CONFINE_RECUR_STRUCT
#define DEBUG_EQV_OBJ_CALC
//#define ENABLE_PTO_PATH_COVERAGE_TEST

//options related to eqv obj search limitations.
#define MAX_EQV_OBJ_ITER 3
#define MAX_EQV_OBJ_NUM 16

#define EF_PATH_TRIM_THRESHOLD 128

namespace DRCHECKER {
//#define DEBUG_FUNCTION_ARG_OBJ_CREATION

    class AliasObject;
    typedef std::pair<CallContext*, CallContext*> PSIG;

    //In some cases our cross-entry object matching may fail to identify some shared objects, because their alias relationship is established
    //somewhere outside our analysis scope and cannot be captured by access path identity as well (e.g., both a->b and d->e->g are set to point
    //to a same object by code outside our analysis scope).
    //For this situation, we design a mechanism that allows the user to manually specify some object types of which they believe the objects
    //must be shared across entries (e.g., "kvm" between vcpu_ioctl() and kvm_ioctl() in kvm driver), we will then take this type set into
    //account when performing the cross-entry object matching.
    extern std::set<std::string> sharedObjTyStrs;

    //This records the objects that are of the types specified in the above "sharedObjTyStrs".
    extern std::map<std::string,std::set<AliasObject*>> sharedObjCache;

    extern Function *currEntryFunc;

    //Optional variables to restrict eqv obj chain explosion.
    extern unsigned MAX_EQV_OBJ_ENUM_CNT;
    extern void *curEqvEnumObj;
    extern unsigned curEqvEnumCnt;

    /***
     * Handles general points to relation.
     */
    // TODO: we should merge the ObjectPointsTo and PointerPoiontsTo later,
    // now the separation makes less sense.
    class ObjectPointsTo {
    public:
        // The src pointer that points to, even it's an obj field pto record,
        // sometimes it can be useful to know which top-level ptr the record
        // comes from (e.g., with a store IR).
        // But by default this member is only inited when constructing a
        // PointerPointsTo, ObjectPointsTo simply carries it over.
        Value *targetPointer = nullptr;
        // the source object and field that points to the target object and field.
        long fieldId = 0;
        AliasObject *srcObject = nullptr;
        // field id of the destination object to which this pointer points tp
        long dstfieldId = 0;
        // object to which we point to.
        AliasObject *targetObject = nullptr;
        // instruction which resulted in this points to information.
        InstLoc *propagatingInst = nullptr;
        // The load tag is designed to hold the memory access path for a pto record of a top-level llvm var,
        // this can help us solve the N*N update problem.
        // e.g.
        // %0 <-- load src   (say src points to 6 mem locs, each of which holds a pointer that has 2 pointees, so %0 will have 12 ptos)
        // %1 = GEP %0, off0 (#pto will remain the same between %0 and %1 (or less due to some filtering logics) for non-load IRs)
        // %2 = GEP %0, off1
        // %3 <-- load %1    (in theory %1 has 12 #ptos now, assume each also holds a pointer who has 2 pointees, so %3 has 24 #pto)
        // store %3 --> %2   (will we do a 24*12 update? No, the correct way is a 12*2*1 update...) 
        // Imagine we now have the load tag for every pointee of %3 (who has 2-layer loads from "src"):
        // src_pointee[0-11] --> %1_pointee[0-23]
        // and that for %2 (1 layer load from src):
        // src_pointee[0-11]
        // By inspecting the load tags of %3 and %2, we can naturally have 12*2*1 pto pairs by "src_pointee[0-11]".
        // Same to "targetPointer", this is now only setup in PointerPointsTo.
        std::vector<TypeField*> loadTag;
        // We want to record how a pointer can end up pointing to a certain object,
        // e.g., 
        // p->f = kmalloc(); //obj 0
        // if (...) {
        //      p->f = kmalloc(); // obj 1
        // }
        // ptr = p->f;
        // "ptr" has two pto records for obj 0 and 1 respectively and these two ptos
        // have the same "propagatingInst" (i.e., ptr = p->f). but it's also interesting
        // to know by following which path "ptr" can point to obj 0 and by which obj 1,
        // such info can be useful for a path-sensitive data flow verification for a
        // warning. In some sense, this history is similar to a "TaintFlag"...
        // One thing to note is that we can only record instructions related to address
        // taken memory objects (e.g., load & store), for top-level variables, since the
        // SSA form, we can always easily complete the history by querying the def-use.
        std::vector<InstLoc*> propagatingHistory;
        //Whether this pto record is a weak update (e.g. the original dst pointer points to multiple locations in multiple objects,
        //so we are not sure whether this pto will be for sure updated for a certain object field at the 'propagatingInst').
        //NOTE that this concept is only useful when updating the object fieldPointsTo 
        //(i.e. for address-taken llvm objects), while for top-level variables (e.g. %x),
        //when we update its pto record we always know which top-level variable is to be updated (i.e. always a strong update).
        bool is_weak = false;
        //Whether this pto establishment directly leads to the creation of a placeholder dummy object.
        //E.g., load o->f0 but o->f0 points to nothing, so we create a dummy "o1", let o->f0 point to o1,
        //and set this "is_creation" flag to "true" in the pto record. 
        bool is_creation = false;
        //For customized usage.
        //E.g. when processing GEP, sometimes we may convert all indices into a single offset and 
        //skip "processGEPMultiDimension", use this flag to indicate this.
        int flag = 0;
        //indicates whether this pto record is currently active (e.g. may be invalidated by another strong post-dom pto update.).
        bool is_active = true;

        ObjectPointsTo() {
            this->flag = 0;
            this->is_active = true;
        }

        ~ObjectPointsTo() {
        }

        ObjectPointsTo(AliasObject *srcObject, long fieldId, AliasObject *targetObject, long dstfieldId, 
                       InstLoc *propagatingInst = nullptr, bool is_weak = false) 
        {
            this->targetPointer = nullptr;
            this->fieldId = fieldId;
            this->srcObject = srcObject;
            this->targetObject = targetObject;
            this->dstfieldId = dstfieldId;
            this->addProp(propagatingInst);
            this->is_weak = is_weak;
            this->flag = 0;
            this->is_active = true;
            this->is_creation = false;
        }

        ObjectPointsTo(ObjectPointsTo *pto):
        ObjectPointsTo(pto->srcObject,pto->fieldId,pto->targetObject,pto->dstfieldId,pto->propagatingInst,pto->is_weak) {
            this->is_active = pto->is_active;
            this->is_creation = pto->is_creation;
            this->loadTag = pto->loadTag;
            this->propagatingHistory = pto->propagatingHistory;
            this->targetPointer = pto->targetPointer;
        }

        //A wrapper for convenience.
        ObjectPointsTo(AliasObject *targetObject, long dstfieldId, InstLoc *propagatingInst = nullptr, bool is_Weak = false):
        ObjectPointsTo(nullptr,0,targetObject,dstfieldId,propagatingInst,is_Weak) {
        }

        void addProp(InstLoc *propInstLoc) {
            this->propagatingInst = propInstLoc;
            this->add2History(propInstLoc);
        }

        void add2History(InstLoc *loc) {
            if (!loc) {
                return;
            }
            if (this->propagatingHistory.empty() ||
                this->propagatingHistory.back() != loc) {
                this->propagatingHistory.push_back(loc);
            }
            return;
        }

        virtual ObjectPointsTo* makeCopy() {
            return new ObjectPointsTo(this);
        }

        virtual bool same(const ObjectPointsTo *that) const {
            if (!that || !this->isIdenticalPointsTo(that)) {
                return false;
            }
            //Additionally, compare the "propagatingInstruction".
            if (!this->propagatingInst != !that->propagatingInst) {
                return false;
            }
            if (this->propagatingInst && this->propagatingInst != that->propagatingInst) {
                return false;
            }
            return true;
        }

        //NOTE: this comparison doesn't consider the additional properties including "propagatingInst" and "is_weak"
        virtual bool isIdenticalPointsTo(const ObjectPointsTo *that) const {
            if (!that) {
                return false;
            }
            return this->fieldId == that->fieldId &&
                   this->pointsToSameObject(that);
        }

        virtual bool pointsToSameObject(const ObjectPointsTo *that) const {
            if(that != nullptr) {
                return this->targetObject == that->targetObject && this->dstfieldId == that->dstfieldId;
            }
            return false;
        }

        virtual long getTargetType() const {
            // Simple polymorphism.
            return 1;
        }

        /*virtual std::ostream& operator<<(std::ostream& os, const ObjectPointsTo& obj) {
            os << "Field :" << fieldId << " points to " << dstfieldId <<" of the object, with ID:" << obj.targetObject;
            return os;
        }*/
        friend llvm::raw_ostream& operator<< (llvm::raw_ostream& os, const ObjectPointsTo& obj) {
            os << "Field :" << obj.fieldId << " points to " << obj.dstfieldId <<" of the object, with ID:" << obj.targetObject;
            return os;
        }

        void print(llvm::raw_ostream& OS);

        void printProp(llvm::raw_ostream& OS, bool complete = false, bool lbreak = false);

        int inArray(Type *ety);

        //If current pto points to an array element, this can change the pto to another desired element in the same array.
        int switchArrayElm(Type *ty, long fid);
    };


    /***
     * Handles the pointer point to relation.
     */
    class PointerPointsTo: public ObjectPointsTo {
    public:
        const static long TYPE_CONST=2;

        PointerPointsTo(PointerPointsTo *srcPointsTo): ObjectPointsTo(srcPointsTo) {
            this->targetPointer = srcPointsTo->targetPointer;
            this->loadTag = srcPointsTo->loadTag;
        }

        PointerPointsTo(Value *targetPointer, AliasObject *srcObject, long fieldId, AliasObject *targetObject, long dstfieldId, 
                        InstLoc *propagatingInst = nullptr, bool is_Weak = false): 
        ObjectPointsTo(srcObject, fieldId, targetObject, dstfieldId, propagatingInst, is_Weak) 
        {
            this->targetPointer = targetPointer;
        }

        //A wrapper for convenience
        PointerPointsTo(Value *targetPointer, AliasObject *targetObject, long dstfieldId, 
                        InstLoc *propagatingInst = nullptr, bool is_Weak = false): 
        PointerPointsTo(targetPointer, nullptr, 0, targetObject, dstfieldId, propagatingInst, is_Weak) 
        {
            //
        }

        PointerPointsTo() {
        }

        ObjectPointsTo *makeCopy() {
            return new PointerPointsTo(this);
        }

        PointerPointsTo *makeCopyP() {
            return new PointerPointsTo(this);
        }

        //We want to copy only a part of current pto but replace the remainings.
        PointerPointsTo *makeCopyP(Value *targetPointer, AliasObject *targetObject, long dstfieldId,
                                   InstLoc *propagatingInst = nullptr, bool is_Weak = false)
        {
            PointerPointsTo *pto = new PointerPointsTo(targetPointer,targetObject,dstfieldId,propagatingInst,is_Weak);
            pto->fieldId = this->fieldId;
            pto->srcObject = this->srcObject;
            pto->loadTag = this->loadTag;
            pto->propagatingHistory = this->propagatingHistory;
            pto->add2History(propagatingInst);
            return pto;
        }

        //A wrapper for convenience.
        PointerPointsTo *makeCopyP(Value *targetPointer, InstLoc *propagatingInst = nullptr, bool is_Weak = false) {
            return this->makeCopyP(targetPointer,this->targetObject,this->dstfieldId,propagatingInst,is_Weak);
        }

        long getTargetType() const {
            // Simple polymorphism.
            return PointerPointsTo::TYPE_CONST;
        }

        bool isIdenticalPointsTo(const ObjectPointsTo *that) const {
            if (that && that->getTargetType() == PointerPointsTo::TYPE_CONST) {
                PointerPointsTo* actualObj = (PointerPointsTo*)that;
                return this->targetPointer == actualObj->targetPointer &&
                       this->targetObject == actualObj->targetObject &&
                       this->fieldId == actualObj->fieldId &&
                       this->dstfieldId == actualObj->dstfieldId;
            }
            return false;
        }

        /*std::ostream& operator<<(std::ostream& os, const ObjectPointsTo& obj) {
            PointerPointsTo* actualObj = (PointerPointsTo*)(&obj);
            os << "Pointer:";
            os << actualObj->targetPointer->getName().str();
            os << " from field:" << fieldId <<" points to field:"<< dstfieldId <<" of the object, with ID:" << this->targetObject;
            return os;
        }*/

        friend llvm::raw_ostream& operator<<(llvm::raw_ostream& os, const PointerPointsTo& obj) {
            PointerPointsTo* actualObj = (PointerPointsTo *)(&obj);
            os << "Pointer:";
            os << actualObj->targetPointer->getName().str();
            os << " from field:" << obj.fieldId <<" points to field:"<< obj.dstfieldId <<" of the object, with ID:" << obj.targetObject;
            return os;
        }

        void print(llvm::raw_ostream& OS);
    };


    static unsigned long idCount;

    static unsigned long getCurrID() {
        return idCount++;
    }

    //A single InstLoc (along with some extra info) on the EqvPath.
    class EqvPathNode {
    public:
        ObjectPointsTo *pto;
        //0: escape, 1: escape/fetch
        int label;
        //Literal values of the "label".
        static const int ESCAPE = 0, FETCH = 1;

        EqvPathNode(ObjectPointsTo *pto, int label) {
            this->pto = pto;
            this->label = label;
        }
        //Test whether two nodes are the same.
        bool same(std::shared_ptr<EqvPathNode> n) {
            if (!n || n->label != this->label) {
                return false;
            }
            if (!this->pto != !n->pto) {
                return false;
            }
            if (this->pto && !this->pto->same(n->pto)) {
                return false;
            }
            return true;
        }
    };

    //This abstracts a path following which an object can reach its one identical
    //object (e.g., escape to a certain access path in one entry and then retrieved
    //through a same access path in a different entry).
    class EqvPath {
    public:
        EqvPath() {}
        EqvPath(std::vector<std::shared_ptr<EqvPathNode>> &path) {
            this->path = path;
        }
        EqvPath(EqvPath *other) {
            assert(other && "Null EqvPath ptr passed in the copy constructor!");
            this->path = other->path;
        }
        //Connect two paths together, e.g., obj0 escapes to access path 0 and then
        //is fetched, and then escapes to another access path 1 again and is fetched..
        EqvPath *connect(EqvPath *other) {
            EqvPath *np = new EqvPath(this);
            if (!other) {
                return np;
            }
            //Append other's path.
            np->path.insert(np->path.end(),other->path.begin(),other->path.end());
            return np;
        }
        //Add a path node to the end.
        void adde(std::shared_ptr<EqvPathNode> n) {
            if (n) {
                this->path.push_back(n);
            }
        }
        //Add a path node to the front.
        void addf(std::shared_ptr<EqvPathNode> n) {
            if (n) {
                this->path.insert(this->path.begin(),n);
            }
        }
        //Test whether another EqvPath is the same as this one.
        bool same(EqvPath *p) {
            if (!p || p->path.size() != this->path.size()) {
                return false;
            }
            for (unsigned i = 0; i < this->path.size(); ++i) {
                if (!this->path[i]->same(p->path[i])) {
                    return false;
                }
            }
            return true;
        }
        //Return the paired path node index related to the given one.
        int getPairedIndex(unsigned idx) {
            if (idx >= this->path.size()) {
                return -1;
            }
            if (!this->path[idx]) {
                return -1;
            }
            //The escape/fetch path is organized in a way that N escape is always followed
            //by the same amount of fetch, and the paired e/f nodes are always mirrored
            //by the middle switch point (e.g., ..., E0, E1, F1, F0, ...).
            if (this->path[idx]->label == EqvPathNode::ESCAPE) {
                //Locate the paired fetch node.
                for (int cnt = 0; ++idx < this->path.size(); ++cnt) {
                    if (this->path[idx]->label == EqvPathNode::FETCH) {
                        if (idx + cnt < this->path.size() && this->path[idx + cnt] &&
                            this->path[idx + cnt]->label == EqvPathNode::FETCH) 
                        {
                            return idx + cnt;
                        }
                        return -1;
                    }
                }
            } else if (this->path[idx]->label == EqvPathNode::FETCH) {
                //Locate the escape node.
                for (int cnt = 0; --idx >= 0; ++cnt) {
                    if (this->path[idx]->label == EqvPathNode::ESCAPE) {
                        if (idx - cnt >= 0 && this->path[idx - cnt] &&
                            this->path[idx - cnt]->label == EqvPathNode::ESCAPE) 
                        {
                            return idx - cnt;
                        }
                        return -1;
                    }
                }
            }
            return -1;
        }
        //Get the starting/ending calling contexts of this path as a signature.
        void getSig(PSIG &sig, AliasObject *src, AliasObject *dst) {
            //First initial escape.
            for (unsigned i = 0; i < this->path.size(); ++i) {
                if (this->path[i]->label != EqvPathNode::ESCAPE) {
                    break;
                }
                ObjectPointsTo *pto = this->path[i]->pto;
                if (!pto || !pto->propagatingInst || pto->targetObject != src) {
                    continue;
                }
                sig.first = pto->propagatingInst->ctx;
                break;
            }
            //Then ending fetch.
            for (int i = this->path.size() - 1; i >= 0; --i) {
                if (this->path[i]->label != EqvPathNode::FETCH) {
                    break;
                }
                ObjectPointsTo *pto = this->path[i]->pto;
                if (!pto || !pto->propagatingInst || pto->targetObject != dst) {
                    continue;
                }
                sig.second = pto->propagatingInst->ctx;
                break;
            }
        }
        //Print the path out in JSON format.
        void printInJson(llvm::raw_ostream &O) {
            O << "{" << "\"path\":" << "[";
            bool comma = false;
            for (std::shared_ptr<EqvPathNode> n : this->path) {
                if (!n || !n->pto) {
                    continue;
                }
                if (comma) {
                    O << ",";
                }
                O << "{" << "\"label\":" << n->label << ",";
                printInstlocJson(n->pto->propagatingInst,O);
                O << ",\"sf\":" << n->pto->fieldId << ",\"df\":" << n->pto->dstfieldId;
                O << ",\"so\":\"" << (const void*)(n->pto->srcObject) << "\"";
                O << ",\"do\":\"" << (const void*)(n->pto->targetObject) << "\"";
                O << "}";
                comma = true;
            }
            O << "]";
            O << "}";
        }
        unsigned getLength() {
            return this->path.size();
        }
        std::vector<std::shared_ptr<EqvPathNode>> path;
    };

    //This class records the info of a pair of potentially identical objects 
    //(e.g., a dummy and a concrete that can potentially be that dummy).
    class EqvObjPair {
    public:
        EqvObjPair() {}
        EqvObjPair(AliasObject *src, AliasObject *dst) {
            this->src = src;
            this->dst = dst;
            this->trimmed = false;
        }
        EqvObjPair(AliasObject *src, AliasObject *dst,
                   std::set<EqvPath *> &paths, bool trim = false):
        EqvObjPair(src, dst) {
            this->paths = paths;
            if (trim && paths.size() >= EF_PATH_TRIM_THRESHOLD) {
                this->_trimPaths();
            }
        }
        //The copy constructor w/ potentially different src and dst objects, but same path sets.
        EqvObjPair(EqvObjPair *other, AliasObject *newsrc = nullptr, AliasObject *newdst = nullptr) {
            assert(other && "Null EqvObjPair ptr passed in the copy constructor!");
            this->src = (newsrc ? newsrc : other->src);
            this->dst = (newdst ? newdst : other->dst);
            for (EqvPath *p : other->paths) {
                if (p) {
                    this->paths.insert(new EqvPath(p));
                }
            }
            this->trimmed = false;
        }
        //Connect with another EqvObjPair and return a new connected instance
        //(e.g., this->dst == other->src)
        //"trim": if true, try to trim some unimportant paths to prevent path explosion.
        EqvObjPair *connect(EqvObjPair *other, bool trim = true) {
            if (!other || this->dst != other->src) {
                return nullptr;
            }
            //Construct the new connected paths.
            std::set<EqvPath*> nps;
            if ((!this->paths.empty()) && (!other->paths.empty())) {
                //concatenate the two sets.
                for (EqvPath *p0 : this->paths) {
                    if (!p0) {
                        continue;
                    }
                    for (EqvPath *p1 : other->paths) {
                        if (!p1) {
                            continue;
                        }
                        EqvPath *np = p0->connect(p1);
                        if (np) {
                            nps.insert(np);
                        }
                    }
                }
            } else if (!this->paths.empty()) {
                for (EqvPath *p0 : this->paths) {
                    if (!p0) {
                        continue;
                    }
                    nps.insert(new EqvPath(p0));
                }
            } else {
                for (EqvPath *p1 : other->paths) {
                    if (!p1) {
                        continue;
                    }
                    nps.insert(new EqvPath(p1));
                }
            }
            //Construct the new pair.
            EqvObjPair *n = new EqvObjPair(this->src, other->dst, nps, trim);
            return n;
        }
        //Merge the path info from another pair with same src and dst.
        int merge(EqvObjPair *other, bool trim = true) {
            if (!other || other->src != this->src || other->dst != this->dst) {
                return 0;
            }
            //////////////////////
            //For debug.
            if (this->paths.size() >= 128 || other->paths.size() >= 128) {
                dbgs() << "!!! merge(): #path0: " << this->paths.size()
                << ", #path1: " << other->paths.size() << "\n";
            }
            //////////////////////
            bool has_new = false;
            for (EqvPath *ep : other->paths) {
                if (!ep) {
                    continue;
                }
                if (std::find_if(this->paths.begin(), this->paths.end(), [ep](EqvPath *p) {
                        return ep->same(p);
                    }) == this->paths.end()) {
                    this->paths.insert(ep);
                    has_new = true;
                }
            }
            if (has_new) {
                //Since there are new paths inserted, we may need to re-trim.
                this->trimmed = false;
            }
            if (trim && this->paths.size() >= EF_PATH_TRIM_THRESHOLD) {
                this->_trimPaths();
            }
            return 1;
        }
        //Add a path node to the front of every path in this->paths if there are any,
        //create a new path starting with the path node otherwise.
        void addf(std::shared_ptr<EqvPathNode> n) {
            if (n) {
                if (this->paths.size() == 0) {
                    this->paths.insert(new EqvPath());
                }
                for (EqvPath *p : this->paths) {
                    if (p) {
                        p->addf(n);
                    }
                }
            }
        }
        //Add a path node to the end of every path in this->paths if there are any,
        //create a new path ending with the path node otherwise.
        void adde(std::shared_ptr<EqvPathNode> n) {
            if (n) {
                if (this->paths.size() == 0) {
                    this->paths.insert(new EqvPath());
                }
                for (EqvPath *p : this->paths) {
                    if (p) {
                        p->adde(n);
                    }
                }
            }
        }
        //Print the info of this pair in JSON format.
        void printInJson(llvm::raw_ostream &O) {
            O << "{";
            O << "\"so\":\"" << (const void*)(this->src) << "\",";
            O << "\"do\":\"" << (const void*)(this->dst) << "\",";
            //Put in the eqv paths.
            O << "\"paths\":" << "[";
            bool comma = false;
            for (EqvPath *p : this->paths) {
                if (!p) {
                    continue;
                }
                if (comma) {
                    O << ",";
                }
                p->printInJson(O);
                comma = true;
            }
            O << "]";
            O << "}";
        }
        //Return one (this may not be the only one) shortest escape/fetch path.
        EqvPath *getShortestEqvPath() {
            EqvPath *shortest = nullptr;
            for (EqvPath *p : this->paths) {
                if (!p) {
                    continue;
                }
                if (!shortest || p->getLength() < shortest->getLength()) {
                    shortest = p;
                }
            }
            return shortest;
        }
        //"src" reaches "dst" via an EqvPath.
        AliasObject *src = nullptr, *dst = nullptr;
        std::set<EqvPath*> paths;
    private:

        bool trimmed = false;
        // Try to discard some unimportant paths to prevent path explosion.
        // Idea: we mainly care about the initial escaping function
        // and the final fetching function, so among all paths with the
        // same initial and ending functions, we reserve the shortest one.
        void _trimPaths() {
            if (this->trimmed) {
                //Already trimmed!
                return;
            }
            std::map<PSIG, EqvPath*> shortest;
            for (EqvPath *p : this->paths) {
                if (!p) {
                    continue;
                }
                PSIG psig;
                p->getSig(psig, this->src, this->dst);
                if (!psig.first || !psig.second) {
                    //This is quite unusual, need to alert.
                    dbgs() << "!!! _trimPaths(): EF path w/o terminal loc info, for"
                    << " obj pair: " << (const void*)this->src << "->"
                    << (const void*)this->dst << " the path: ";
                    p->printInJson(dbgs());
                    dbgs() << "\n";
                }
                if (shortest.find(psig) == shortest.end()) {
                    shortest[psig] = p;
                } else {
                    if (p->getLength() < shortest[psig]->getLength()) {
                        shortest[psig] = p;
                    }
                }
            }
            //Reserve the shortest paths, and discard the rest.
            std::set<EqvPath*> reserved;
            for (auto &e : shortest) {
                reserved.insert(e.second);
            }
            for (EqvPath *p : this->paths) {
                if (!p) {
                    continue;
                }
                if (reserved.find(p) == reserved.end()) {
                    delete p;
                }
            }
            this->paths = reserved;
            this->trimmed = true;
            //dbgs() << "Path trimmed for obj pair: " << (const void*)this->src << "->"
            //<< (const void*)this->dst << ", #paths: " << this->paths.size() << "\n";
        }
    };

    /***
     * The alias object. Refer Definition 3.7 of the paper.
     */
    class AliasObject {
    public:
        Type *targetType;
        // All pointer variables that can point to this object.
        std::set<PointerPointsTo*> pointersPointsTo;
        // This represents points from information, all objects which can point to this.
        // The key is the src object, the value is the pto records in src object that point to this obj.
        std::map<AliasObject*,std::set<ObjectPointsTo*>> pointsFrom;
        // All Objects that could be pointed by this object.
        // The key is the field number, the value is all pto records of this field.
        std::map<long,std::set<ObjectPointsTo*>> pointsTo;
        // The reference instruction of this AliasObject (usually the inst where this obj is created.).
        InstLoc *refInst = nullptr;
        // The locations where this object is read, field -> read InstLoc
        std::map<long,std::map<InstLoc*, std::set<PointerPointsTo*>>> reads;
        // The locations where this object is written, field -> write InstLoc
        std::map<long,std::map<InstLoc*, std::set<PointerPointsTo*>>> writes;
        // The object write with a recognizable pattern (e.g., a trait set).
        std::map<long,std::map<TraitSet*, std::set<InstLoc*>>> tsets;

        //A "forward eqv object" is an identical object that can be reached via an (escape->fetch)* path,
        //starting from this object (e.g., this object first escapes to an access path, which is fetched 
        //later and results in an identical placeholder dummy object).
        //If this object is dummy, it also has a set of "backward eqv object", which can reach current 
        //dummy obj via an (escape->fetch)* path.
        //map: dst eqv obj -> the details of the pair
        std::map<AliasObject*,EqvObjPair*> *fEqvObjs = nullptr, *bEqvObjs = nullptr;
        //The *All version stores all eqv objects through recursively tracing the (escape->fetch) paths.
        std::map<AliasObject*,EqvObjPair*> *fEqvObjsAll = nullptr, *bEqvObjsAll = nullptr;

        //Information needed for Taint Analysis.
        // fields that store information which is tainted.
        std::vector<FieldTaint*> taintedFields;

        bool auto_generated = false;

        //Hold the taint flags that are effective for all fields, we use a special "FieldTaint" (fid=-1) for it.
        FieldTaint all_contents_taint_flags;

        // flag which indicates whether the object is initialized or not.
        // by default every object is initialized.
        bool is_initialized = true;
        // the set of instructions which initialize this object
        std::set<Instruction*> initializingInstructions;

        // Record the InstLocs where this obj is freed (e.g., kfree() invocation),
        // along with the pto records used at the F site to obtain the object.
        std::map<InstLoc*, std::set<PointerPointsTo*>> freeSites;

        // Whether this object is immutable.
        bool is_const = false;

        unsigned long id;

        //hz: indicate whether this object is a taint source.
        int is_taint_src = 0;

        //hz: This maps the field to the corresponding object (embedded) if the field is an embedded struct in the host object.
        std::map<long,AliasObject*> embObjs;

        //hz: it's possible that this obj is embedded in another obj.
        AliasObject *parent = nullptr;
        long parent_field;

        unsigned long getID() const{
            return this->id;
        }

        AliasObject(AliasObject *srcAliasObject) {
            assert(srcAliasObject != nullptr);
            this->targetType = srcAliasObject->targetType;
            this->pointersPointsTo.insert(srcAliasObject->pointersPointsTo.begin(), srcAliasObject->pointersPointsTo.end());
            this->pointsFrom = srcAliasObject->pointsFrom;
            this->pointsTo = srcAliasObject->pointsTo;
            this->id = getCurrID();
            this->lastPtoReset = srcAliasObject->lastPtoReset;

            this->is_initialized = srcAliasObject->is_initialized;
            this->initializingInstructions.insert(srcAliasObject->initializingInstructions.begin(),
                                                  srcAliasObject->initializingInstructions.end());
            this->is_const = srcAliasObject->is_const;
            //this->is_taint_src = srcAliasObject->is_taint_src;
            this->embObjs = srcAliasObject->embObjs;
            this->parent = srcAliasObject->parent;
            this->parent_field = srcAliasObject->parent_field;
            this->refInst = srcAliasObject->refInst;
            this->reads = srcAliasObject->reads;
            this->writes = srcAliasObject->writes;
        }

        AliasObject() {
            //hz: init some extra fields
            this->id = getCurrID();
            this->parent = nullptr;
            this->parent_field = 0;
            this->refInst = nullptr;
        }

        ~AliasObject() {
            // delete all object pointsTo and the related pointsFrom in other objects.
            for (auto &x : pointsTo) {
                for (ObjectPointsTo *pto : x.second) {
                    if (pto->targetObject) {
                        pto->targetObject->erasePointsFrom(this,pto);
                    }
                    delete(pto);
                }
            }
            // delete all field taint.
            for(auto ft:taintedFields) {
                delete(ft);
            }
        }
        
        //"forward": true means that we are updating fowardEqvObj map (e.g., the key is the dst obj
        //in an escape->fetch path while the map is for the src obj), otherwise it's a backwardEqvObj map.
        int add2EqvMap(std::map<AliasObject*,EqvObjPair*> *m, EqvObjPair *eq, bool forward = true) {
            if (!m || !eq) {
                return 0;
            }
            AliasObject *key = (forward ? eq->dst : eq->src);
            if (!key) {
                return 0;
            }
            if (m->find(key) == m->end() || !(*m)[key]) {
                (*m)[key] = eq;
                return 1;
            }
            (*m)[key]->merge(eq);
            delete(eq);
            return 2;
        }

        //Return the fetch edge(s) (e.g., result in a newly created dummy obj) associated 
        //with the specified field.
        int getFetchEdges(long fid, std::set<ObjectPointsTo*> &res) {
            if (this->pointsTo.find(fid) == this->pointsTo.end()) {
                return 0;
            }
            for (ObjectPointsTo *pto : this->pointsTo[fid]) {
                if (pto && pto->is_creation) {
                    res.insert(pto);
                }
            }
            return 1;
        }

        //Return the escape edges (i.e., basically all the field pto records).
        int getEscapeEdges(long fid, std::set<ObjectPointsTo*> &res) {
            if (this->pointsTo.find(fid) == this->pointsTo.end()) {
                return 0;
            }
            for (ObjectPointsTo *pto : this->pointsTo[fid]) {
                if (pto) {
                    res.insert(pto);
                }
            }
            return 1;
        }

        //Try to prevent the explosive recursion.
        int validateEqvStack(std::vector<AliasObject*> &history, AliasObject *curr) {
            //Global counter update.
            AliasObject *cObj = (history.empty() ? curr : history[0]);
            if (cObj == DRCHECKER::curEqvEnumObj) {
                ++DRCHECKER::curEqvEnumCnt;
            } else {
                DRCHECKER::curEqvEnumObj = cObj;
                DRCHECKER::curEqvEnumCnt = 1;
            }
            if (DRCHECKER::MAX_EQV_OBJ_ENUM_CNT > 0) {
                //There is a hardcoded (by user) limit for the max #chains that
                //should be traversed.
                if (DRCHECKER::curEqvEnumCnt > DRCHECKER::MAX_EQV_OBJ_ENUM_CNT) {
                    //Indicate that the caller (at every layer) should return
                    //immediately
                    return -9;
                }
            }
            //(1) Two same obj instance on the satck will cause an infinite recursion, so stop searching.
            //(2) Multiple recursive structure related nodes (e.g., list_head) on the stack may cause lengthy recursion, so stop.
#ifdef CONFINE_RECUR_STRUCT
            std::string nty;
            if (curr && curr->targetType) {
                nty = InstructionUtils::isRecurTy(curr->targetType);
            }
#endif
            for (AliasObject *obj : history) {
                if (obj == curr) {
                    //Case (1)
                    return -1;
                }
#ifdef CONFINE_RECUR_STRUCT
                if (!nty.empty() && obj) {
                    std::string hty = InstructionUtils::getTypeName(obj->targetType);
                    InstructionUtils::trim_num_suffix(&hty);
                    if (hty == nty) {
                        //Case (2)
                        return -2;
                    }
                }
#endif
            }
            //(3) If the stack is already deep, we will stop searching if it contains two same-typed objects.
            if (history.size() > 1) {
                for (AliasObject *obj : history) {
                    if (curr && obj && InstructionUtils::same_types(curr->targetType,obj->targetType)) {
                        return -3;
                    }
                }
            }
            return 0;
        }
        
        //Try to get the forward eqv objects of "this", note that this function considers
        //only one layer of "escape-fetch" (e.g., obj0 escapes to a certain path following which obj1
        //is retrieved later, but obj1 may again escape to another path and be fetched later, so on
        //and so forth.).
        //"history" is a stack that records all the objects that are pending on this recursive call.
        int getForwardEqvObjsOnce(std::vector<AliasObject*> &history, std::map<AliasObject*,EqvObjPair*> &res) {
            int err = 0;
            res.clear();
            if (this->fEqvObjs) {
                //Results already cached.
                res = *(this->fEqvObjs);
                return 0;
            }
#ifdef DEBUG_EQV_OBJ_CALC
            std::string DPRE;
            for (auto &o : history) {
                DPRE += "  ";
            }
            DPRE += "getForwardEqvObjsOnce(): ";
            dbgs() << DPRE << "for obj: " << (const void*)this << "\n";
#endif
            //See whether we should stop searching eqv objs on current obj history (e.g., self-recursion).
            err = validateEqvStack(history,this);
            if (err < 0) {
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << DPRE << "invalid history, stop searching ("
                << err << ")\n";
#endif
                return err;
            }
            bool search_aborted = false;
            //Start searching..
            //(0) First add the obj itself to the result, w/ a null eqv path.
            EqvObjPair *spair = new EqvObjPair(this,this);
            res[this] = spair;
            //(1) Host object (this is embedded in another object)
            if (this->parent) {
                AliasObject *ho = this->parent;
                long hf = this->parent_field;
                //(1)-1 collect the forward eqv objects of the host object...
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << DPRE << "search for forward eqv through the emb-host obj: "
                << (const void*)ho << "\n";
#endif
                history.push_back(this);
                std::map<AliasObject *, EqvObjPair *> r;
                if ((err = ho->getForwardEqvObjsOnce(history, r)) < 0) {
                    search_aborted = true;
                }
                history.pop_back();
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << DPRE << "RES: ";
#endif
                //Get the corresponding embedded objects within the forward eqv objs of the host.
                for (auto &e : r) {
                    AliasObject *eo = e.first->getEmbObj(hf);
                    if (!eo || !eo->isDummy() || eo == this ||
                        !InstructionUtils::same_types(this->targetType, eo->targetType, true)) {
                        continue;
                    }
#ifdef DEBUG_EQV_OBJ_CALC
                    dbgs() << "~>" << (const void*)e.first << ":" << (const void*)eo << ", ";
#endif
                    //Got one forward eqv obj!
                    //TODO: do we need to add the "refInst" of the two emb objs to the eqv path?
                    EqvObjPair *newpair = new EqvObjPair(e.second, this, eo);
                    add2EqvMap(&res, newpair);
                }
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << "\n";
#endif
                //(1)-2 consider the pto records to the emb field within the host object (but not directly to this emb object).
                //TODO
            }
            //-------------------------------------------------------------------
            //(2) PointerPointsTo (this can be pointed to by a top-level pointer variable)
            //(2)-1 If the pointer is a function local variable, due to the SSA form, it has only one
            //"assign" site, at which it either receives certain pointees (escaped to it) or leads to
            //the creation of one dummy obj (fetch), in the former case there is no fetch path so we can
            //ignore (remember we need to find forward eqv objs through escape-fetch), in the latter
            //case there is only one object (i.e., "this"), so again we can ignore..
            //(2)-2 The pointer is global, in this case, LLVM will create a global pointer's pointer
            //(e.g., source level "data *p" becomes "data **@p" at IR level), and our analysis will
            //create a GlobalObject to be pointed to by this pointer's pointer (e.g., @p points to an
            //object whose type is "data*"), so we only need to look at the "this->pointsFrom" and no
            //need to analyze "this->pointerPointsFrom"..
            //-------------------------------------------------------------------
            //(3) PointsFrom (this can be pointed to by a field in another object)
            for (auto &e : this->pointsFrom) {
                //We only care about the pto records which point to the base of "this".
                if (!e.first) {
                    continue;
                }
                std::set<ObjectPointsTo*> ptos;
                for (ObjectPointsTo *pto : e.second) {
                    if (pto && pto->dstfieldId == 0) {
                        ptos.insert(pto);
                    }
                }
                if (ptos.empty()) {
                    continue;
                }
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << DPRE << "search for forward eqv obj through points-from obj: "
                << (const void*)e.first << ", #ptos: " << ptos.size() << "\n";
#endif
                //Ok, get the forward eqv objects of the pointer obj.
                AliasObject *o = e.first;
                std::map<AliasObject *, EqvObjPair *> r;
                history.push_back(this);
                int err = o->getForwardEqvObjsOnce(history, r);
                if (err < 0) {
                    search_aborted = true;
                }
                history.pop_back();
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << DPRE << "RES: ";
#endif
                for (auto &eq : r) {
                    AliasObject *eqo = eq.first;
                    EqvObjPair *eqp = eq.second;
                    for (ObjectPointsTo *pto : ptos) {
                        long sfid = pto->fieldId;
                        //Current situation: "this" is pointed to by (or escapes to) "o" at field "sfid"
                        //(recorded in "pto"), while "eqo" is a forward eqv obj to "o".
                        //What we need do: check whether "eqo" has any fetch edge at "sfid", if so, the
                        //fetched dummy obj can be a forward eqv obj to "this".
                        std::set<ObjectPointsTo*> fetches;
                        eqo->getFetchEdges(sfid,fetches);
                        for (ObjectPointsTo *fetch : fetches) {
                            //Some basic check on whether the fetched object can be potentially identical to "this".
                            AliasObject *fo = fetch->targetObject;
                            if (!fo || !fo->isDummy() || fo == this ||
                                !InstructionUtils::same_types(this->targetType,fo->targetType,true)) {
                                    continue;
                            }
#ifdef DEBUG_EQV_OBJ_CALC
                            dbgs() << (const void*)this << "-(esc:" <<  (const void*)pto << ")->"
                            << (const void*)o << "|" << sfid << "~>" << (const void*)eqo
                            << "|" << sfid << "-(fet:" << (const void*)fetch << ")->"
                            << (const void*)fo << ", ";
#endif
                            //Got a new forward eqv obj ("fo") to "this", create the new EqvObjPair record.
                            EqvObjPair *newpair = new EqvObjPair(eqp,this,fo);
                            //Insert the escape path node from "this" to "o".
                            newpair->addf(std::shared_ptr<EqvPathNode>(
                                          new EqvPathNode(pto,EqvPathNode::ESCAPE)));
                            //Append the fetch path node from "eqo" to "fo".
                            newpair->adde(std::shared_ptr<EqvPathNode>(
                                          new EqvPathNode(fetch,EqvPathNode::FETCH)));
                            //Done, add to the result set..
                            add2EqvMap(&res,newpair);
                        }
                    }
                }
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << "\n";
#endif
                if (err == -9) {
                    break;
                }
            } //Enumerate the points-from records.
            //Fill in the cache if all recursions have been finished..
            if (history.empty() || !search_aborted) {
                this->fEqvObjs = new std::map<AliasObject *, EqvObjPair *>(res);
            }
            return err;
        }

        //Try to get all the forward eqv objects of "this", in this function we will recursively
        //explore all layers of "escape->fetch" path until reaching a fixed point.
        int getForwardEqvObjs(std::map<AliasObject*,EqvObjPair*> &res) {
            DRCHECKER::curEqvEnumObj = nullptr;
            res.clear();
            if (this->fEqvObjsAll) {
                res = *(this->fEqvObjsAll);
                return 0;
            }
#ifdef DEBUG_EQV_OBJ_CALC
            dbgs() << "getForwardEqvObjs(): for obj: " << (const void*)this << "\n";
#endif
            //First the object itself is obviously an eqv.
            EqvObjPair *spair = new EqvObjPair(this,this);
            res[this] = spair;
            //The new eqv objs that need to be recursively explored in the next iteration.
            std::set<AliasObject *> newEqvs = {this};
            int n_iter = 0;
            while (!newEqvs.empty()) {
#ifdef DEBUG_EQV_OBJ_CALC
                auto t_st = std::chrono::system_clock::now();
#endif
                std::set<AliasObject *> currNewObjs;
                for (AliasObject *o : newEqvs) {
                    //Get one layer escape-fetch eqv obj for each newly identified obj.
                    std::map<AliasObject *, EqvObjPair *> tmp;
                    std::vector<AliasObject *> history;
                    o->getForwardEqvObjsOnce(history, tmp);
                    //Merge the results and see whether we have got any new eqv objs.
                    for (auto &e : tmp) {
                        AliasObject *no = e.first;
                        if (res.find(no) != res.end()) {
                            //The new eqv obj is already in the result set, ignore.
                            //TODO: maybe we should add new "eqv" path - though the obj already exists,
                            //reaching here means "this" can reach it through a different (longer) (escape->fetch)*
                            //path, but for now we only reserve the shortest path.
                        } else {
                            //Add the newly found eqv obj and construct the new eqv path from "this".
                            //Current situation: "this" can already reach "o" through an eqv path, and
                            //"o" can reach "no" through another, so we need to stitch the two paths together
                            //for the new eqv pair "this" and "no".
                            EqvObjPair *eqp1 = e.second;
                            //Simple checks.
                            assert(eqp1 && "eqp1 must not be nullptr!");
                            assert(no == eqp1->dst && "no == eqp1->dst");
                            if (this == o) {
                                res[no] = eqp1;
                            } else {
                                EqvObjPair *eqp0 = res[o];
                                //Simple checks.
                                assert(eqp0 && "eqp0 must not be nullptr!");
                                assert(o == eqp0->dst && "o == eqp0->dst");
                                //Connect the two eqv paths and make a new EqvObjPair.
                                EqvObjPair *neqp = eqp0->connect(eqp1);
                                if (!neqp) {
                                    dbgs() << "!!! getForwardEqvObjs(): failed to connect eqps!\n";
                                    continue;
                                }
                                res[no] = neqp;
                            }
                            //We need to recursively identify the eqv obj of "no" in the next round.
                            currNewObjs.insert(no);
                        }
                    }// for: enumerate pairs from "o" to "no" 
                }//for: iterate through each new eqv obj "o".
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << "getForwardEqvObjs(): iteration: " << n_iter << ", src objs: ";
                for (AliasObject *so : newEqvs) {
                    dbgs() << (const void*)so << ", ";
                }
                dbgs() << "new res objs: ";
                for (AliasObject *so : currNewObjs) {
                    dbgs() << (const void*)so << ", ";
                }
                std::chrono::duration<double> e_sec = std::chrono::system_clock::now() - t_st;
                dbgs() << "time spent (s): " << e_sec.count() << "\n";
#endif
                //Before the next iteration, we should consider whether it's the time to
                //stop the search - we may already have many eqv objs, and in most cases,
                //one-iteration search is enough to discover the cross-entry UAFs.
                ++n_iter;
#ifdef MAX_EQV_OBJ_ITER
                if (n_iter >= MAX_EQV_OBJ_ITER) {
#ifdef DEBUG_EQV_OBJ_CALC
                    dbgs() << "getForwardEqvObjs(): max iteration reached!\n";
#endif
                    break;
                }
#endif
#ifdef MAX_EQV_OBJ_NUM
                if (res.size() >= MAX_EQV_OBJ_NUM) {
#ifdef DEBUG_EQV_OBJ_CALC
                    dbgs() << "getForwardEqvObjs(): max eqv obj num reached!\n";
#endif
                    break;
                }
#endif
                newEqvs = currNewObjs;
            }
            //Done, cache the results.
            this->fEqvObjsAll = new std::map<AliasObject *, EqvObjPair *>(res);
#ifdef DEBUG_EQV_OBJ_CALC
            dbgs() << "getForwardEqvObjs(): done, the forward objs of "
            << (const void*)this << " are: ";
            for (auto &e : res) {
                dbgs() << (const void*)e.first << ", ";
            }
            dbgs() << "\n";
#endif
            return 1;
        }

        //Get backward eqv objs of "this" through one layer of (escape->fetch) path, e.g., obj0 escapes to a certain
        //access path and then retrieved through the same path as "this", thus obj0 is a backward eqv obj of "this".
        int getBackwardEqvObjsOnce(std::vector<AliasObject*> &history, std::map<AliasObject*,EqvObjPair*> &res) {
            int err = 0;
            res.clear();
            if (this->bEqvObjs) {
                //Results cached.
                res = *(this->bEqvObjs);
                return 0;
            }
#ifdef DEBUG_EQV_OBJ_CALC
            std::string DPRE;
            for (auto &o : history) {
                DPRE += "  ";
            }
            DPRE += "getBackwardEqvObjsOnce(): ";
            dbgs() << DPRE << "for obj: " << (const void*)this << "\n";
#endif
            //See whether we should stop searching eqv objs on current obj history (e.g., self-recursion).
            err = validateEqvStack(history,this);
            if (err < 0) {
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << DPRE << "invalid history, stop searching ("
                << err << ")\n";
#endif
                return err;
            }
            bool search_aborted = false;
            //As the definition implies, only a dummy obj can have backward eqv objs, since the
            //backward eqv path ends w/ a "fetch". But an only exception is that the obj is always
            //equivalent to itself.
            EqvObjPair *spair = new EqvObjPair(this,this);
            res[this] = spair;
            if (!this->isDummy()) {
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << DPRE << "this is not a dummy obj, so its back eqv obj is just itself.\n";
#endif
                this->bEqvObjs = new std::map<AliasObject*,EqvObjPair*>(res);
                return 0;
            }
            //(0) Go through the nested obj hierarchy.
            if (this->parent) {
                AliasObject *ho = this->parent;
                long hf = this->parent_field;
                //(1)-1 collect the backward eqv objects of the host object...
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << DPRE << "search for backward eqv through the emb-host obj: "
                << (const void*)ho << "\n";
#endif
                history.push_back(this);
                std::map<AliasObject *, EqvObjPair *> r;
                if ((err = ho->getBackwardEqvObjsOnce(history, r)) < 0) {
                    search_aborted = true;
                }
                history.pop_back();
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << DPRE << "RES: ";
#endif
                //Get the corresponding embedded objects within the backward eqv objs of the host.
                for (auto &e : r) {
                    AliasObject *eo = e.first->getEmbObj(hf);
                    if (!eo || eo == this ||
                        !InstructionUtils::same_types(this->targetType, eo->targetType, true)) {
                        continue;
                    }
#ifdef DEBUG_EQV_OBJ_CALC
                    dbgs() << (const void*)e.first << ":" << (const void*)eo << "~>, ";
#endif
                    //Got one backward eqv obj!
                    //TODO: do we need to add the "refInst" of the two emb objs to the eqv path?
                    EqvObjPair *newpair = new EqvObjPair(e.second, eo, this);
                    add2EqvMap(&res, newpair, false);
                }
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << "\n";
#endif
                //(1)-2 consider the pto records to the emb field within the host object (but not directly to this emb object).
                //TODO
            }
            //NOTE: we can ignore pointersPointsTo, w/ a similar reasoning as in getForwardEqvObjsOnce().
            //(1) Iterate through the "pointsFrom" record.
            for (auto &e : this->pointsFrom) {
                //We only care about the pto records which point to the base of "this".
                //Besides, only when "this" dummy obj is fetched by a parent obj, we need
                //to further explore the parent, because we're looking for the backward
                //eqv obj (it must reach "this" with an escape->*fetch* path).
                if (!e.first) {
                    continue;
                }
                std::set<ObjectPointsTo*> ptos;
                for (ObjectPointsTo *pto : e.second) {
                    if (pto && pto->is_creation && pto->dstfieldId == 0) {
                        ptos.insert(pto);
                    }
                }
                if (ptos.empty()) {
                    continue;
                }
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << DPRE << "search for backward eqv obj through points-from obj: "
                << (const void*)e.first << ", #ptos: " << ptos.size() << "\n";
#endif
                //Ok, get the backward eqv objects of the points-from obj.
                AliasObject *o = e.first;
                std::map<AliasObject *, EqvObjPair *> r;
                history.push_back(this);
                err = o->getBackwardEqvObjsOnce(history, r);
                if (err < 0) {
                    search_aborted = true;
                }
                history.pop_back();
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << DPRE << "RES: ";
#endif
                for (auto &eq : r) {
                    AliasObject *eqo = eq.first;
                    EqvObjPair *eqp = eq.second;
                    for (ObjectPointsTo *pto : ptos) {
                        long sfid = pto->fieldId;
                        //Current situation: "this" is fetched by "o" at field "sfid" (recorded in "pto"), 
                        //while "eqo" is a backward eqv obj to "o".
                        //What we need do: check whether any objs escape to "eqo" at "sfid" - they are backward
                        //eqv objs of "this".
                        std::set<ObjectPointsTo*> escapes;
                        eqo->getEscapeEdges(sfid,escapes);
                        for (ObjectPointsTo *escape : escapes) {
                            //Some basic check on whether the escaping object can be potentially identical to "this".
                            AliasObject *eso = escape->targetObject;
                            if (!eso || eso == this ||
                                !InstructionUtils::same_types(this->targetType,eso->targetType,true)) {
                                    continue;
                            }
#ifdef DEBUG_EQV_OBJ_CALC
                            dbgs() << (const void*)eso << "-(esc:" <<  (const void*)escape << ")->"
                            << (const void*)eqo << "|" << sfid << "~>" << (const void*)o
                            << "|" << sfid << "-(fet:" << (const void*)pto << ")->"
                            << (const void*)this << ", ";
#endif
                            //Got a new backward eqv obj ("eso") to "this", create the new EqvObjPair record.
                            EqvObjPair *newpair = new EqvObjPair(eqp,eso,this);
                            //Insert the escape path node from "eso" to "eqo".
                            newpair->addf(std::shared_ptr<EqvPathNode>(
                                          new EqvPathNode(escape,EqvPathNode::ESCAPE)));
                            //Append the fetch path node from "o" to "this".
                            newpair->adde(std::shared_ptr<EqvPathNode>(
                                          new EqvPathNode(pto,EqvPathNode::FETCH)));
                            //Done, add to the result set..
                            add2EqvMap(&res,newpair,false);
                        }
                    }
                }
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << "\n";
#endif
                if (err == -9) {
                    break;
                }
            } //Enumerate the points-from records.
            //Fill in the cache if all recursions have been finished..
            if (history.empty() || !search_aborted) {
                this->bEqvObjs = new std::map<AliasObject *, EqvObjPair *>(res);
            }
            return err;
        }

        //Try to get all the backward eqv objects of "this", in this function we will recursively
        //explore all layers of "escape->fetch" path until reaching a fixed point.
        int getBackwardEqvObjs(std::map<AliasObject*,EqvObjPair*> &res) {
            DRCHECKER::curEqvEnumObj = nullptr;
            res.clear();
            if (this->bEqvObjsAll) {
                res = *(this->bEqvObjsAll);
                return 0;
            }
#ifdef DEBUG_EQV_OBJ_CALC
            dbgs() << "getBackwardEqvObjs(): for obj: " << (const void*)this << "\n";
#endif
            //First the object itself is obviously an eqv.
            EqvObjPair *spair = new EqvObjPair(this,this);
            res[this] = spair;
            //The new eqv objs that need to be recursively explored in the next iteration.
            std::set<AliasObject *> newEqvs = {this};
            int n_iter = 0;
            while (!newEqvs.empty()) {
#ifdef DEBUG_EQV_OBJ_CALC
                auto t_st = std::chrono::system_clock::now();
#endif
                std::set<AliasObject *> currNewObjs;
                for (AliasObject *o : newEqvs) {
                    //Get one layer escape-fetch eqv obj for each newly identified obj.
                    std::map<AliasObject *, EqvObjPair *> tmp;
                    std::vector<AliasObject *> history;
                    o->getBackwardEqvObjsOnce(history, tmp);
                    //Merge the results and see whether we have got any new eqv objs.
                    for (auto &e : tmp) {
                        AliasObject *no = e.first;
                        if (res.find(no) != res.end()) {
                            //The new eqv obj is already in the result set, ignore.
                            //TODO: maybe we should add new "eqv" path - though the obj already exists,
                            //reaching here means it can reach "this" through a different (longer) (escape->fetch)*
                            //path, but for now we only reserve the shortest path.
                        } else {
                            //Add the newly found eqv obj and construct the new eqv path to "this".
                            //Current situation: "o" can already reach "this" through an eqv path, and
                            //"no" can reach "o" through another, so we need to stitch the two paths together
                            //for the new eqv pair "no" and "this".
                            EqvObjPair *eqp1 = e.second;
                            //Simple checks.
                            assert(eqp1 && "eqp1 must not be nullptr!");
                            assert(no == eqp1->src && "no == eqp1->src");
                            if (this == o) {
                                res[no] = eqp1;
                            } else {
                                EqvObjPair *eqp0 = res[o];
                                //Simple checks.
                                assert(eqp0 && "eqp0 must not be nullptr!");
                                assert(o == eqp0->src && "o == eqp0->src");
                                //Connect the two eqv paths and make a new EqvObjPair.
                                EqvObjPair *neqp = eqp1->connect(eqp0);
                                if (!neqp) {
                                    dbgs() << "!!! getBackwardEqvObjs(): failed to connect eqps!\n";
                                    continue;
                                }
                                res[no] = neqp;
                            }
                            //We need to recursively identify the backward eqv obj of "no" in the next round,
                            //if "no" is dummy (i.e., concrete objs do not have backward eqv objs).
                            if (no->isDummy()) {
                                currNewObjs.insert(no);
                            }
                        }
                    }// for: enumerate pairs from "o" to "no" 
                }//for: iterate through each new eqv obj "o".
#ifdef DEBUG_EQV_OBJ_CALC
                dbgs() << "getBackwardEqvObjs(): iteration: " << n_iter << ", src objs: ";
                for (AliasObject *so : newEqvs) {
                    dbgs() << (const void*)so << ", ";
                }
                dbgs() << "new res objs: ";
                for (AliasObject *so : currNewObjs) {
                    dbgs() << (const void*)so << ", ";
                }
                std::chrono::duration<double> e_sec = std::chrono::system_clock::now() - t_st;
                dbgs() << "time spent (s): " << e_sec.count() << "\n";
#endif
                ++n_iter;
                //Search limitation if configured.
#ifdef MAX_EQV_OBJ_ITER
                if (n_iter >= MAX_EQV_OBJ_ITER) {
#ifdef DEBUG_EQV_OBJ_CALC
                    dbgs() << "getBackwardEqvObjs(): max iteration reached!\n";
#endif
                    break;
                }
#endif
#ifdef MAX_EQV_OBJ_NUM
                if (res.size() >= MAX_EQV_OBJ_NUM) {
#ifdef DEBUG_EQV_OBJ_CALC
                    dbgs() << "getBackwardEqvObjs(): max eqv obj num reached!\n";
#endif
                    break;
                }
#endif
                newEqvs = currNewObjs;
            }
            //Done, cache the results.
            this->bEqvObjsAll = new std::map<AliasObject *, EqvObjPair *>(res);
#ifdef DEBUG_EQV_OBJ_CALC
            dbgs() << "getBackwardEqvObjs(): done, the backward objs of "
            << (const void*)this << " are: ";
            for (auto &e : res) {
                dbgs() << (const void*)e.first << ", ";
            }
            dbgs() << "\n";
#endif
            return 1; 
        }

        //Get all eqv objs to "this", including both forward and backward ones.
        int getEqvObjs(std::map<AliasObject*,EqvObjPair*> &res) {
            std::map<AliasObject*,EqvObjPair*> fres, bres;
#ifdef DEBUG_EQV_OBJ_CALC
            dbgs() << "getEqvObjs(): for obj: " << (const void*)this << "\n";
#endif
            this->getForwardEqvObjs(fres);
            this->getBackwardEqvObjs(bres);
            res = fres;
            res.insert(bres.begin(),bres.end());
#ifdef DEBUG_EQV_OBJ_CALC
            dbgs() << "getEqvObjs(): done, for obj: " << (const void*)this << ", #res: "
            << res.size() << "\n";
#endif
            //NOTE: if an obj is both forward and backward eqv to "this", we will only add it once
            //and reserve its forward EqvObjPair in the final result.
            return 0;
        }

        //Record a location where this object is freed.
        int markFree(InstLoc *loc, PointerPointsTo *pto) {
            if (!loc || !pto) {
                return -1;
            }
            this->freeSites[loc].insert(pto);
            return 0;
        }

        int addAccessSite(long fid, InstLoc *loc, PointerPointsTo *pto, bool read = true) {
            if (!loc || !pto) {
                return 0;
            }
            //We always store the access info to the innermost embedded fields if any.
            AliasObject *o = this->getNestedObj(fid,nullptr,loc);
            if (o && o != this) {
                return o->addAccessSite(0,loc,pto,read);
            }
            //Choose a map to update
            auto &m = (read ? this->reads : this->writes);
            m[fid][loc].insert(pto);
            return 1;
        }

        bool addTraitSet(long fid, TraitSet *ts, InstLoc *loc) {
            if (!ts || !loc) {
                return false;
            }
            //We always store the info to the innermost embedded fields if any.
            AliasObject *o = this->getNestedObj(fid,nullptr,loc);
            if (o && o != this) {
                return o->addTraitSet(0,ts,loc);
            }
            //Do the update.
            this->tsets[fid][ts].insert(loc);
            return true;
        }

        //Find all InstLocs that has a TraitSet for "fid" of this object, that can kill the
        //desired branch ("dst") of the given "tc". 
        int getKillerTraitSetLocs(TraitCheck *tc, unsigned dst, long fid, std::set<InstLoc*> &res) {
            if (!tc || this->tsets.find(fid) == this->tsets.end()) {
                return 0;
            }
            res.clear();
            for (auto &e : this->tsets[fid]) {
                TraitSet *ts = e.first;
                assert(ts);
                /*
                ///////////////////////////
                dbgs() << "getKillerTraitSetLocs(): got one TraitSet: ";
                ts->print(dbgs(), false);
                dbgs() << " for TraitCheck: ";
                tc->print(dbgs(), false);
                dbgs() << ", dst: " << dst << "\n";
                ///////////////////////////
                */
                std::set<InstLoc*> &locs = e.second;
                if (ts->kill(tc,dst)) {
                    res.insert(locs.begin(),locs.end());
                }
            }
            return 1;
        }

        //"fid": "-1" means to return access sites of all fields
        //"ty": "-1" -> read, "1" -> write, "0" -> both
        //NOTE: in this function we also need to consider the access sites of the embed/host objects.
        int getAccessSites(long fid, std::set<InstLoc*> &res, int ty = 0) {
            std::set<InstLoc *> tmp;
            //First insert the records in this object.
            if (ty <= 0) {
                if (fid < 0) {
                    for (auto &x : this->reads) {
                        for (auto &x0 : x.second) {
                            tmp.insert(x0.first);
                        }
                    }
                } else if (this->reads.find(fid) != this->reads.end()) {
                    for (auto &x : this->reads[fid]) {
                        tmp.insert(x.first);
                    }
                }
            }
            if (ty >= 0) {
                if (fid < 0) {
                    for (auto &x : this->writes) {
                        for (auto &x0 : x.second) {
                            tmp.insert(x0.first);
                        }
                    }
                } else if (this->writes.find(fid) != this->writes.end()) {
                    for (auto &x : this->writes[fid]) {
                        tmp.insert(x.first);
                    }
                }
            }
            //If the specified field(s) is an embedded object, we need to recursively obtain its access sites.
            std::set<long> fids = {fid};
            if (fid < 0) {
                std::set<long> allFids = this->getAllAvailableFields();
                fids.insert(allFids.begin(), allFids.end());
            }
            for (long i : fids) {
                AliasObject *o = this->getEmbObj(i);
                if (o) {
                    o->getAccessSites(-1,tmp,ty);
                }
            }
            //NOTE: we will ensure that the access info is always stored in the innermost object in the nest hierarchy,
            //so no need to lookup the access info in the host object - if any - of current one.
            //Put locs into the final "res".
            res.insert(tmp.begin(), tmp.end());
            return 1;
        }

        //Get all the free sites of "this" object as a whole.
        int getFreeSites(std::set<InstLoc*> &res) {
            //We should count all free sites for either "this" object or one of its host objects.
            AliasObject *obj = this;
            while (obj) {
                if (!obj->freeSites.empty()) {
                    for (auto &e : obj->freeSites) {
                        res.insert(e.first);
                    }
                }
                obj = obj->parent;
            }
            return 0;
        }

        //Given a F loc, return all the pto records used at that loc to retrieve this
        //object to free.
        std::set<PointerPointsTo*> *getFreePtos(InstLoc *floc) {
            if (!floc) {
                return nullptr;
            }
            AliasObject *obj = this;
            while (obj) {
                if (!obj->freeSites.empty() && 
                    obj->freeSites.find(floc) != obj->freeSites.end()) {
                    return &(obj->freeSites[floc]);
                }
                obj = obj->parent;
            }
            return nullptr;
        }

        //Given a U loc, return all the pto records used at that loc to retrieve this
        //object to use.
        int getUsePtos(InstLoc *uloc, std::set<PointerPointsTo*> &res) {
            if (!uloc) {
                return 0;
            }
            for (auto &e : this->reads) {
                for (auto &e0 : e.second) {
                    if (uloc == e0.first) {
                        res.insert(e0.second.begin(), e0.second.end());
                    }
                }
            }
            for (auto &e : this->writes) {
                for (auto &e0 : e.second) {
                    if (uloc == e0.first) {
                        res.insert(e0.second.begin(), e0.second.end());
                    }
                }
            }
            //Don't forget the access info stored in the emb objs.
            for (auto &e : this->embObjs) {
                AliasObject *eobj = e.second;
                if (eobj) {
                    eobj->getUsePtos(uloc,res);
                }
            }
            return 0;
        }

        //Get all the free sites that free the memory associated with the "fid" field in this object,
        //note that we need to conisder both the host object and embedded object at "fid".
        int getFieldFreeSites(long fid, std::set<InstLoc*> &res) {
            std::set<InstLoc*> tmp;
            //First, whatever "fid" is specified, as long as the whole object or its host object is freed, the field
            //must also be freed..
            this->getFreeSites(res);
            //Second, the embedded object at the "fid" may be freed separately.
            std::set<AliasObject*> eobjs;
            this->getEmbObjs(fid,eobjs);
            while (!eobjs.empty()) {
                std::set<AliasObject*> tobjs;
                for (AliasObject *o : eobjs) {
                    if (!o) {
                        continue;
                    }
                    if (!o->freeSites.empty()) {
                        for (auto &e : o->freeSites) {
                            res.insert(e.first);
                        }
                    }
                    o->getEmbObjs(0,tobjs);
                }
                //Recursively get all heading embedded objects.
                eobjs.clear();
                eobjs = tobjs;
            }
            return 0;
        }

        //Similar to "getFieldFreeSites", this function tries to get the allocation site of the specified field within current object,
        //the difference is that there can only be one allocation site.
        InstLoc *getFieldAllocSite(long fid) {
            //First search for allocation sites of the host objects.
            AliasObject *obj = this;
            InstLoc *loc = nullptr;
            while (obj) {
                if (obj->isHeapLocation()) {
                    loc = obj->getAllocLoc();
                    if (loc) {
                        return loc;
                    }
                }
                obj = obj->parent;
            }
            //Then search for the allocation sites of the embedded objects at the specified field.
            std::set<AliasObject*> eobjs;
            this->getEmbObjs(fid,eobjs);
            while (!eobjs.empty()) {
                std::set<AliasObject*> tobjs;
                for (AliasObject *o : eobjs) {
                    if (!o) {
                        continue;
                    }
                    if (o->isHeapLocation()) {
                        loc = o->getAllocLoc();
                        if (loc) {
                            return loc;
                        }
                    }
                    o->getEmbObjs(0,tobjs);
                }
                eobjs.clear();
                eobjs = tobjs;
            }
            return nullptr;
        }

        //Decide whether this obj can be a recursive structure node by inspecting
        //its field types, note that we want to be conservative here and avoid
        //the overkill (e.g., a list_head in a struct may not mean that this struct
        //is a rec node - maybe it's just a member link list managed by this struct).
        //For now we require to meet all the following conditions:
        //(1) there is a pointer field pointing to the same type as the host struct;
        //(2) the field has been actively used (e.g., there are pto records on it).
        bool isRecNode() {
            if (!this->targetType || !dyn_cast<StructType>(this->targetType)) {
                return false;
            }
            StructType *stTy = dyn_cast<StructType>(this->targetType);
            for (unsigned i = 0; i < stTy->getNumElements(); ++i) {
                Type *ety = stTy->getElementType(i);
                if (!ety) {
                    continue;
                }
                if (ety->isPointerTy() &&
                    InstructionUtils::same_types(ety->getPointerElementType(), stTy))
                {
                    //See whether this field has been used.
                    if (this->pointsTo.find(i) != this->pointsTo.end() &&
                        !this->pointsTo[i].empty())
                    {
                        //TODO: Should we consider the location of the field use?
                        return true;
                    }
                    //TODO: also consider name based identification (e.g., .next, .prev).
                }
            }
            return false;
        }

        //"E" means that we need to consider the emb obj hierarchy, e.g., we may need
        //to create an emb obj as a field of a heap obj, but the emb obj by default
        //is an OutsideObj instead of HeapLocation, to decide the real type, we need to
        //walk through the emb hierarchy.
        bool isHeapLocationE(InstLoc **aloc = nullptr) {
            AliasObject *o = this;
            while (o) {
                if (o->isHeapLocation()) {
                    if (aloc) {
                        *aloc = o->getAllocLoc();
                    }
                    return true;
                }
                o = o->parent;
            } 
            return false;
        }

        //Similar to above.
        bool isFunctionLocalE() {
            AliasObject *o = this;
            while (o) {
                if (o->isFunctionLocal()) {
                    return true;
                }
                o = o->parent;
            } 
            return false;
        }

        bool isGlobalObjectE() {
            AliasObject *o = this;
            while (o) {
                if (o->isGlobalObject()) {
                    return true;
                }
                o = o->parent;
            } 
            return false;
        }

        //Imagine that we invoke a memcpy() to make a copy of "this" object, in this case, we need to reserve
        //the original pto and taint info, recursively copy the embedded objs, but give up records like "pointsFrom"...
        //NOTE: if "loc" is specified, we should copy only the pto and taint facts that are valid at "loc".
        AliasObject *makeCopy(InstLoc *loc, AliasObject *pobj = nullptr) {
#ifdef DEBUG_OBJ_COPY
            dbgs() << "AliasObject::makeCopy(): try to make a copy of obj: " << (const void*)this << "\n";
#endif
            AliasObject *obj = (pobj ? pobj : new AliasObject());
            obj->targetType = this->targetType;
            //Copy the "pointTo" records, note that we cannot simply copy the ObjectPointsTo*, instead we need to make a copy of each
            //ObjectPointsTo, besides, we also need to update the "pointsFrom" record of each field pointee obj (to add the newly created
            //"obj" as a new src object).
            for (auto &e : this->pointsTo) {
                std::set<ObjectPointsTo*> ptos, *ps = &(e.second);
                if (loc) {
                    this->getLivePtos(e.first,loc,&ptos);
                    ps = &ptos;
                }
                for (ObjectPointsTo *pto : *ps) {
                    if (pto && pto->targetObject) {
                        ObjectPointsTo *npto = new ObjectPointsTo(pto);
                        npto->srcObject = obj;
                        (obj->pointsTo)[e.first].insert(npto);
                        npto->targetObject->addPointsFrom(obj,npto);
                    }
                }
            }
            obj->lastPtoReset = this->lastPtoReset;
            obj->is_initialized = this->is_initialized;
            obj->initializingInstructions = this->initializingInstructions;
            obj->is_const = this->is_const;
            obj->auto_generated = this->auto_generated;
            /*
            obj->is_taint_src = this->is_taint_src;
            //Copy all the taint flags for each field.
            for (FieldTaint *ft : this->taintedFields) {
                if (!ft) {
                    continue;
                }
                FieldTaint *nft = ft->makeCopy(obj,loc);
                obj->taintedFields.push_back(nft);
            }
            //Copy all_contents_taint_flags
            obj->all_contents_taint_flags.reset(this->all_contents_taint_flags.makeCopy(obj,loc));
            */
            //Recursively copy the embedded objs, if any.
            for (auto &e : this->embObjs) {
                AliasObject *eo = e.second;
                if (eo) {
                    AliasObject *no = eo->makeCopy(loc);
                    if (no) {
                        (obj->embObjs)[e.first] = no;
                    }else {
                        //Is this possible...
                        dbgs() << "!!! AliasObject::makeCopy(): failed to make a copy of the emb object: " << (const void*)eo << "\n";
                    }
                }
            }
#ifdef DEBUG_OBJ_COPY
            dbgs() << "AliasObject::makeCopy(): copy created: " << (const void*)obj << "\n";
#endif
            return obj;
        }

        //Merge the field pto and TFs from another object w/ the same type, at the "loc".
        void mergeObj(AliasObject *obj, InstLoc *loc, bool is_weak) {
#ifdef DEBUG_OBJ_COPY
            dbgs() << "AliasObject::mergeObj(): try to merge obj: " << (const void*)obj << " -> " << (const void*)this << "\n";
#endif
            if (!obj || !InstructionUtils::same_types(obj->targetType,this->targetType) || !loc) {
#ifdef DEBUG_OBJ_COPY
                dbgs() << "AliasObject::mergeObj(): sanity check failed, return.\n";
#endif
                return;
            }
            //Merge the pto records of each field.
            int wflag = (is_weak ? 1 : 0);
            for (auto &e : obj->pointsTo) {
                std::set<ObjectPointsTo*> ptos;
                obj->getLivePtos(e.first,loc,&ptos);
                if (!ptos.empty()) {
                    this->updateFieldPointsTo(e.first,&ptos,loc,wflag);
                }
            }
            /*
            //Merge the "all_contents_taint_flags".
            std::set<TaintFlag*> tfs;
            obj->all_contents_taint_flags.getTf(loc,tfs);
            for (TaintFlag *tf : tfs) {
                //The reachability from this "tf" to "loc" has already been ensured by "getTf()",
                //so it's safe to directly copy the "tf" w/ the new target instruction "loc".
                TaintFlag *ntf = new TaintFlag(tf,loc);
                ntf->is_weak |= is_weak;
                this->taintAllFields(ntf);
            }
            //Merge the TFs from each field.
            for (FieldTaint *ft : obj->taintedFields) {
                if (ft) {
                    //First get live all taints for the field.
                    tfs.clear();
                    ft->getTf(loc,tfs);
                    for (TaintFlag *tf : tfs) {
                        TaintFlag *ntf = new TaintFlag(tf,loc);
                        ntf->is_weak |= is_weak;
                        this->addFieldTaintFlag(ft->fieldId,ntf);
                    }
                }
            }
            */
            //Recursively merge each embedded object.
            for (auto &e : obj->embObjs) {
                AliasObject *sobj = e.second;
                AliasObject *dobj = nullptr;
                if (this->embObjs.find(e.first) == this->embObjs.end()) {
                    //This means we need to create the required embedded object to receive the data from "obj".
                    dobj = this->createEmbObj(e.first,nullptr,loc);
                }else {
                    dobj = (this->embObjs)[e.first];
                }
                if (sobj && dobj) {
                    dobj->mergeObj(sobj,loc,is_weak);
                }
            }
#ifdef DEBUG_OBJ_COPY
            dbgs() << "AliasObject::mergeObj(): done: " << (const void*)obj << " -> " << (const void*)this << "\n";
#endif
        }

        //Merge a specified field in another object to "fid" of "this", including its pto and TFs.
        void mergeField(long fid, AliasObject *mobj, long mfid, InstLoc *loc, bool is_weak) {
#ifdef DEBUG_OBJ_COPY
            dbgs() << "AliasObject::mergeField(): " << (const void*)mobj << "|" << mfid << " -> " << (const void*)this 
            << "|" << fid << "\n";
#endif
            //First need to make sure the src and dst field have the same type.
            if (!mobj || !loc) {
                return;
            }
            Type *dty = this->getNonCompFieldTy(fid);
            Type *sty = mobj->getNonCompFieldTy(mfid);
            if (!InstructionUtils::same_types(sty,dty,true)) {
#ifdef DEBUG_OBJ_COPY
                dbgs() << "AliasObject::mergeField(): type mismatch.\n";
#endif
                return;
            }
            //Propagate the pto record.
            std::map<AliasObject*, std::set<long>> dstObjs;
            std::set<ObjectPointsTo*> rps;
            //NOTE: here we will not try to create dummy pointee objects
            //(i.e. just propagate the pto as is).
            mobj->fetchPointsToObjects(mfid,rps,loc,true,false);
            for (ObjectPointsTo *pto : rps) {
                if (pto && pto->targetObject) {
                    dstObjs[pto->targetObject].insert(pto->dstfieldId);
                }
            }
            for (auto &e : dstObjs) {
                AliasObject *pobj = e.first;
                for (long pfid : e.second) {
                    this->addObjectToFieldPointsTo(fid,pobj,loc,is_weak,pfid);
                }
            }
            //Propagate the taint.
            /*
            std::set<TaintFlag*> tfs;
            mobj->getFieldTaintInfo(mfid,tfs,loc);
            for (TaintFlag *tf : tfs) {
                TaintFlag *ntf = new TaintFlag(tf,loc);
                ntf->is_weak |= is_weak;
                this->addFieldTaintFlag(fid,ntf);
            }
            */
        }

        //If "act" is negative, return # of all pto on file, otherwise, only return active/inactive pto records.
        unsigned long countObjectPointsTo(long srcfieldId, int act = -1) {
            /***
             * Count the number of object-field combinations that could be pointed by
             * a field (i.e srcfieldId).
            */
            if (this->pointsTo.find(srcfieldId) == this->pointsTo.end()) {
                return 0;
            }
            if (act < 0) {
                return this->pointsTo[srcfieldId].size();
            }
            int num = 0;
            for (ObjectPointsTo *pto : this->pointsTo[srcfieldId]) {
                if (pto && pto->is_active == !!act) {
                    ++num;
                }
            }
            return num;
        }

        int addPointerPointsTo(PointerPointsTo *pto) {
            //Basic sanity check.
            if (!pto || pto->targetObject != this) {
                return 0;
            }
            InstLoc *loc = pto->propagatingInst;
            //De-duplication
            bool is_dup = false;
            for (PointerPointsTo *p : this->pointersPointsTo) {
                if (!p) {
                    continue;
                }
                if (!loc != !p->propagatingInst) {
                    continue;
                }
                if (pto->isIdenticalPointsTo(p) && (!loc || loc == p->propagatingInst)) {
                    is_dup = true;
                    break;
                }
            }
            if (is_dup) {
                return 0;
            }
            this->pointersPointsTo.insert(pto);
            return 1;
        }

        int addPointerPointsTo(Value *p, InstLoc *loc, long dfid = 0) {
            if (!p) {
                return 0;
            }
            //NOTE: default is_Weak setting (i.e. strong update) is ok for top-level vars.
            PointerPointsTo *newPointsTo = new PointerPointsTo(p,this,dfid,loc,false);
            //De-duplication
            int r = this->addPointerPointsTo(newPointsTo);
            if (!r) {
                delete(newPointsTo);
            }
            return r;
        }

        //update the "pointsFrom" records.
        bool addPointsFrom(AliasObject *srcObj, ObjectPointsTo *pto) {
            if (!srcObj || !pto) {
                return false;
            }
            //validity check
            if (pto->targetObject != this) {
                return false;
            }
            if (this->pointsFrom.find(srcObj) == this->pointsFrom.end()) {
                this->pointsFrom[srcObj].insert(pto);
            }else {
                //Detect the duplication.
                auto it = std::find_if(this->pointsFrom[srcObj].begin(), this->pointsFrom[srcObj].end(), [pto](const ObjectPointsTo *n) {
                            return  n->fieldId == pto->fieldId && n->dstfieldId == pto->dstfieldId;
                            });
                if (it == this->pointsFrom[srcObj].end()) {
                    this->pointsFrom[srcObj].insert(pto);
                }else {
                    //Just activate the existing pto record.
                    (*it)->is_active = true;
                }
            }
            return true;
        }

        //If "act" is negative, the specified pto record will be removed, otherwise, its "is_active" field will be set to "act".
        bool erasePointsFrom(AliasObject *srcObj, ObjectPointsTo *pto, int act = -1) {
            if (!srcObj || !pto || this->pointsFrom.find(srcObj) == this->pointsFrom.end()) {
                return true;
            }
            for (auto it = this->pointsFrom[srcObj].begin(); it != this->pointsFrom[srcObj].end(); ) {
                ObjectPointsTo *p = *it;
                if (p->fieldId == pto->fieldId && p->dstfieldId == pto->dstfieldId) {
                    if (act < 0) {
                        it = this->pointsFrom[srcObj].erase(it);
                    }else {
                        //Just deactivate the pointsFrom record w/o removing it.
                        p->is_active = !!act;
                        ++it;
                    }
                }else {
                    ++it;
                }
            }
            return true;
        }

        //activate/de-activate the field pto record.
        void activateFieldPto(ObjectPointsTo *pto, bool activate = true) {
            if (!pto) {
                return;
            }
            if (activate) {
                pto->is_active = true;
                if (pto->targetObject) {
                    pto->targetObject->erasePointsFrom(this,pto,1);
                }
            }else {
                pto->is_active = false;
                if (pto->targetObject) {
                    pto->targetObject->erasePointsFrom(this,pto,0);
                }
            }
            return;
        }

        //Get the type of a specific field in this object.
        Type *getFieldTy(long fid, int *err = nullptr) {
            return InstructionUtils::getTypeAtIndex(this->targetType, fid, err);
        }

        //Sometimes the field itself can be another embedded struct, this function intends to return all types at a specific field.
        void getNestedFieldTy(long fid, std::set<Type*> &retSet) {
            Type *ety = (fid ? this->getFieldTy(fid) : this->targetType);
            InstructionUtils::getHeadTys(ety,retSet);
            return;
        }

        //At the field there may be en embedded struct, in this function we just return the non-composite type (should be only 1) at "fid".
        Type *getNonCompFieldTy(long fid) {
            Type *ety = (fid ? this->getFieldTy(fid) : this->targetType);
            if (!InstructionUtils::isCompTy(ety)) {
                return ety;
            }
            return InstructionUtils::getHeadTy(ety);
        }

        //We want to get all possible pointee types of a certain field, so we need to 
        //inspect the detailed type desc (i.e. embed/parent object hierarchy).
        void getFieldPointeeTy(long fid, std::set<Type*> &retSet) {
            if (this->pointsTo.find(fid) == this->pointsTo.end()) {
                return;
            }
            for (ObjectPointsTo *obj : this->pointsTo[fid]) {
                if (obj->fieldId == fid) {
                    if (!obj->targetObject) {
                        continue;
                    }
                    obj->targetObject->getNestedFieldTy(obj->dstfieldId,retSet);
                }
            }
            return;
        }

        void logFieldPto(long fid, raw_ostream &O) {
            if (this->pointsTo.find(fid) == this->pointsTo.end()) {
                return;
            }
            int total = 0, act = 0, strong = 0;
            for (ObjectPointsTo *pto : this->pointsTo[fid]) {
                if (pto) {
                    ++total;
                    if (pto->is_active) {
                        ++act;
                    }
                    if (!pto->is_weak) {
                        ++strong;
                    }
                }
            }
            O << "Field Pto: " << (const void*)this << " | " << fid << " : " << "#Total: " << total 
            << " #Active: " << act << " #Strong: " << strong << "\n";
        }

        //This is a wrapper of "updateFieldPointsTo" for convenience, it assumes that we only have one pto record for the "fieldId" to update,
        //and this pto points to field 0 (can be customized via "dfid") of "dstObject".
        //TODO: consider to replace more "updateFieldPointsTo" invocation to this when applicable, to simplify the codebase.
        ObjectPointsTo *addObjectToFieldPointsTo(long fieldId, AliasObject *dstObject,
                                                 InstLoc *propagatingInstr = nullptr,
                                                 bool is_weak = false, long dfid = 0,
                                                 bool is_creation = false) {
#ifdef DEBUG_UPDATE_FIELD_POINT
            dbgs() << "addObjectToFieldPointsTo() for: " << InstructionUtils::getTypeName(this->targetType) << " | " << fieldId;
            dbgs() << " Host Obj ID: " << (const void*)this << "\n";
#endif
            if(dstObject != nullptr) {
                std::set<ObjectPointsTo*> dstPointsTo;
                ObjectPointsTo *newPointsTo = new ObjectPointsTo(this,fieldId,dstObject,dfid,propagatingInstr,is_weak);
                newPointsTo->is_creation = is_creation;
                dstPointsTo.insert(newPointsTo);
                std::set<ObjectPointsTo*> res;
                this->updateFieldPointsTo(fieldId,&dstPointsTo,propagatingInstr,-1,&res);
                //We can now delete the allocated objects since "updateFieldPointsTo" has made a copy.
                delete(newPointsTo);
                if (!res.empty()) {
                    return *(res.begin());
                }
            }
            return nullptr;
        }

        //Just return null if there is no embedded object at the specified field.
        AliasObject *getEmbObj(long fieldId) {
            if (this->embObjs.find(fieldId) != this->embObjs.end()) {
                return this->embObjs[fieldId];
            }
            return nullptr;
        }

        //Different from "getEmbObj", this function considers the special "-1" field:
        //if this is a sequential object, we will return embedded objects of all fields if the "-1" fid is specified,
        //besides, the embedded object at "-1" field will also be returned if the arg "fid" is not -1.
        int getEmbObjs(long fid, std::set<AliasObject*> &res) {
            std::set<long> fids = {fid};
            if (InstructionUtils::isSeqTy(this->targetType)) {
                if (fid < 0) {
                    std::set<long> allFids = this->getAllAvailableFields();
                    fids.insert(allFids.begin(),allFids.end());
                }else {
                    fids.insert(-1);
                }
            }
            for (long f : fids) {
                AliasObject *obj = this->getEmbObj(f);
                if (obj) {
                    res.insert(obj);
                }
            }
            return 0;
        }

        //Set the "dstObject" as embedded in field "fieldId".
        bool setEmbObj(long fieldId, AliasObject *dstObject, bool check_ty = false) {
            if (!dstObject) {
                return false;
            }
            if (this->embObjs.find(fieldId) != this->embObjs.end()) {
                //There is already an existing emb obj.
                return false;
            }
            //First check whether the object type matches that of the field, if required.
            if (check_ty) {
                Type *ety = this->getFieldTy(fieldId);
                if (!ety) {
                    return false;
                }
                if (!InstructionUtils::same_types(dstObject->targetType,ety)) {
                    return false;
                }
            }
            //Now embed the object.
            //TODO: what if the "dstObject" already has a host object?
            this->embObjs[fieldId] = dstObject;
            dstObject->parent = this;
            dstObject->parent_field = fieldId;
            return true;
        }

        //get the outermost parent object.
        AliasObject *getTopParent() {
            AliasObject *obj = this;
            while (obj->parent) {
                obj = obj->parent;
            }
            return obj;
        }

        bool getPossibleMemberFunctions_dbg(Instruction *inst, FunctionType *targetFunctionType, Type *host_ty, 
                                            long field, std::vector<Function *> &targetFunctions) {
            if (!inst || !targetFunctionType || !host_ty || field < 0 || field >= host_ty->getStructNumElements()) {
                return false;
            }
            Module *currModule = inst->getParent()->getParent()->getParent();
            for(auto a = currModule->begin(), b = currModule->end(); a != b; a++) {
                Function *currFunction = &(*a);
                if(!currFunction->isDeclaration()) {
                    if (currFunction->getName().str() != "vt_ioctl") {
                        continue;
                    }
                    dbgs() << "Find vt_ioctl()\n";
                    std::map<Type*,std::set<long>> *res = InstructionUtils::getUsesInStruct(currFunction);
                    if (res) {
                        dbgs() << "getUsesInStruct succeed!\n";
                        for (auto& x : *res) {
                            dbgs() << "-------------------\n";
                            dbgs() << InstructionUtils::getTypeName(x.first) << "\n";
                            for (auto &y : x.second) {
                                dbgs() << y << ", ";
                            }
                            dbgs() << "\n";
                        }
                    }
                    for (Value::user_iterator i = currFunction->user_begin(), e = currFunction->user_end(); i != e; ++i) {
                        ConstantExpr *constExp = dyn_cast<ConstantExpr>(*i);
                        ConstantAggregate *currConstA = dyn_cast<ConstantAggregate>(*i);
                        GlobalValue *currGV = dyn_cast<GlobalValue>(*i);
                        dbgs() << "USE: " << InstructionUtils::getValueStr(*i) << "### " << (constExp!=nullptr) 
                        << "|" << (currConstA!=nullptr) << "|" << (currGV!=nullptr) << "\n";
                        if(constExp != nullptr) {
                            for (Value::user_iterator j = constExp->user_begin(), je = constExp->user_end(); j != je; ++j) {
                                ConstantAggregate *currConstAC = dyn_cast<ConstantAggregate>(*j);
                                dbgs() << "USE(CEXPR): " << InstructionUtils::getValueStr(*i) << "### " << (currConstAC!=nullptr) << "\n";
                            }
                        }
                        if(currConstA != nullptr) {
                            dbgs() << "Find its use as a ConstantAggregate:\n";
                            dbgs() << InstructionUtils::getValueStr(currConstA) << "\n";
                            Constant *constF = currConstA->getAggregateElement(12);
                            if (!constF) {
                                dbgs() << "Failure currConstA->getAggregateElement(12)\n";
                                continue;
                            }
                            dbgs() << "constF: " << InstructionUtils::getValueStr(constF) << "\n";
                            Function *dstFunc = dyn_cast<Function>(constF);
                            if (!dstFunc && dyn_cast<ConstantExpr>(constF)) {
                                dbgs() << "!dstFunc && dyn_cast<ConstantExpr>(constF)\n";
                                //Maybe this field is a casted function pointer.
                                ConstantExpr *constE = dyn_cast<ConstantExpr>(constF);
                                if (constE->isCast()) {
                                    dbgs() << "constE->isCast()\n";
                                    Value *op = constE->getOperand(0);
                                    dstFunc = dyn_cast<Function>(op);
                                    //dstFunc might still be null.
                                }
                            }
                            if (dstFunc) {
                                dbgs() << dstFunc->getName().str() << "\n";
                            }else {
                                dbgs() << "Null dstFunc\n";
                            }
                        }
                    }
                }
            }
            return false;
        }

        //Try to find a proper function for a func pointer field in a struct.
        bool getPossibleMemberFunctions(long field, FunctionType *targetFunctionType, Instruction *inst,
                                        std::set<Function*> &targetFunctions) {
            Type *host_ty = this->targetType;
            if (!inst || !targetFunctionType || !InstructionUtils::isCompTy(host_ty)) {
                return false;
            }
            if (!InstructionUtils::isIndexValid(host_ty,field)) {
                return false;
            }
#ifdef DEBUG_SMART_FUNCTION_PTR_RESOLVE
            dbgs() << "getPossibleMemberFunctions: inst: ";
            dbgs() << InstructionUtils::getValueStr(inst) << "\n";
            dbgs() << "FUNC: " << InstructionUtils::getTypeName(targetFunctionType);
            dbgs() << " STRUCT: " << InstructionUtils::getTypeName(host_ty) << " | " << field << "\n";
#endif
            if (!inst->getParent()) {
                return false;
            }
            Module *currModule = inst->getFunction()->getParent();
            std::string fname = "";
            std::string tname = "";
            if (dyn_cast<StructType>(host_ty)) {
                fname = InstructionUtils::getStFieldName(currModule,dyn_cast<StructType>(host_ty),field);
                if (dyn_cast<StructType>(host_ty)->hasName()) {
                    tname = dyn_cast<StructType>(host_ty)->getName().str();
                    InstructionUtils::trim_num_suffix(&tname);
                }
            }
            //Put the potential callees into three categories (from mostly likely to unlikely):
            //(1) Both host struct type and pointer field ID match;
            //(2) TBD;
            //(3) Other potential callees besides (1) and (2).
            std::set<Function*> grp[3];
            for(auto a = currModule->begin(), b = currModule->end(); a != b; a++) {
                Function *currFunction = &(*a);
                // does the current function has same type of the call instruction?
                if (currFunction->isDeclaration() || !InstructionUtils::same_types(currFunction->getFunctionType(), targetFunctionType)) {
                    continue;
                }
#ifdef DEBUG_SMART_FUNCTION_PTR_RESOLVE
                dbgs() << "getPossibleMemberFunctions: Got a same-typed candidate callee: "
                << currFunction->getName().str() << "\n";
#endif
                if (!InstructionUtils::isPotentialIndirectCallee(currFunction)) {
#ifdef DEBUG_SMART_FUNCTION_PTR_RESOLVE
                    dbgs() << "getPossibleMemberFunctions: not a potential indirect callee!\n";
#endif
                    continue;
                }
                //In theory, at this point the "currFunction" can already be a possible callee, we may have FP, but not FN.
                //The below filtering logic (based on the host struct type and field id/name of the function pointer) is to
                //reduce the FP, but in the meanwhile it may introduce FN...
                //TODO: for grp (1) and (2), currently we can only recognize the statically assigned function pointer field
                //(e.g. at the definition site), the dynamically assigned ones will be put into grp (3) now.
                std::map<Type*,std::set<long>> *res = InstructionUtils::getUsesInStruct(currFunction);
                if (!res || res->empty()) {
                    grp[2].insert(currFunction);
                    continue;
                }
                bool match_0 = false, field_name_match = false, exclude = false;
                for (auto& x : *res) {
                    Type *curHostTy = x.first;
                    if (!curHostTy || x.second.empty()) {
                        continue;
                    }
#ifdef DEBUG_SMART_FUNCTION_PTR_RESOLVE
                    dbgs() << "USE: STRUCT: " << InstructionUtils::getTypeName(curHostTy) << " #";
                    for (auto& y : x.second) {
                        dbgs() << y << ", ";
                    }
                    dbgs() << "\n";
#endif
                    if (InstructionUtils::same_types(curHostTy, host_ty)) {
                        if (field == -1 || x.second.find(field) != x.second.end() ||
                            x.second.find(-1) != x.second.end()) 
                        {
#ifdef DEBUG_SMART_FUNCTION_PTR_RESOLVE
                            dbgs() << "getPossibleMemberFunctions: matched! (host | field).\n";
#endif
                            match_0 = true;
                            break;
                        } else {
                            //This means the candidate func takes a different field
                            //within the same struct as the target func, strongly
                            //indicating that the candidate cannot be the target.
                            exclude = true;
                            break;
                        }
                    } else {
                        // This candidate appears in a struct that is of a different
                        // type than the target func.
                        // TODO: what's the best choice? Exclude them or include?
                        exclude = true;
                    }
                    //Not sure what's the implication of "field name match", is it more
                    //likely to match the target due to same field name? Or opposite
                    //because same field name but in different host structs?
                    /*
                    if (dyn_cast<StructType>(curHostTy) && fname != "" && !field_name_match) {
                        for (auto& y : x.second) {
                            std::string curFname = InstructionUtils::getStFieldName(currModule,dyn_cast<StructType>(curHostTy),y);
                            if (curFname == fname) {
#ifdef DEBUG_SMART_FUNCTION_PTR_RESOLVE
                                dbgs() << "getPossibleMemberFunctions: matched! (field name).\n";
#endif
                                field_name_match = true;
                                break;
                            }
                        }
                    }
                    */
                }
                if (match_0) {
                    grp[0].insert(currFunction);
                } else if (!exclude) {
                    grp[2].insert(currFunction);
                }
            }
#ifdef DEBUG_SMART_FUNCTION_PTR_RESOLVE
            dbgs() << "getPossibleMemberFunctions: #grp0: " << grp[0].size() << " #grp1: " << grp[1].size()
            << " #grp2: " << grp[2].size() << "\n";
#endif
            if (grp[0].size() > 0) {
                targetFunctions.insert(grp[0].begin(),grp[0].end());
            }else if (grp[1].size() > 0) {
                targetFunctions.insert(grp[1].begin(),grp[1].end());
            }else {
                targetFunctions.insert(grp[2].begin(),grp[2].end());
                //Reserve only those functions which are part of the driver.
                InstructionUtils::filterPossibleFunctionsByLoc(inst,targetFunctions);
            }
#ifdef DEBUG_SMART_FUNCTION_PTR_RESOLVE
            dbgs() << "getPossibleMemberFunctions: #ret: " << targetFunctions.size() << "\n";
#endif
            return targetFunctions.size() > 0;
        }

        //TaintInfo helpers start

        //This is basically a wrapper of "getTf" in FieldTaint..
        //NOTE: "post_analysis" means whether "getFieldTaintInfo" is invoked after the main analysis has been finished (e.g. in the
        //bug detection phase), if this is the case, since the "active" state of TFs is no longer maintained and updated, we cannot
        //rely on it to filter out TFs any more.
        void getFieldTaintInfo(long fid, std::set<TaintFlag*> &r, InstLoc *loc = nullptr, bool get_eqv = true, bool post_analysis = false, 
                               bool resolve_emb = false) {
            AliasObject *host = this;
            //If required, take care of the potential emb obj at the specified "fid".
            if (resolve_emb) {
                host = this->getNestedObj(fid,nullptr,loc);
                if (!host) {
                    host = this;
                }
                if (host != this) {
                    //This means what we need to fetch is in an embedded field obj at the original "fid", 
                    //so what we should fetch from is the field "0" of the emb "host".
                    fid = 0;
                }
            }
            //Take care of the case where array(s) are involved.
            if (get_eqv) {
                std::set<TypeField*> eqs;
                host->getEqvArrayElm(fid,eqs);
                if (eqs.size() > 1) {
                    for (TypeField *e : eqs) {
                        if (e->fid != fid || e->priv != host) {
#ifdef DEBUG_FETCH_FIELD_TAINT
                            dbgs() << "AliasObject::getFieldTaintInfo(): ~~>[EQV OBJ] " << (const void*)(e->priv) << "|" << e->fid << "\n";
#endif
                            ((AliasObject*)e->priv)->getFieldTaintInfo(e->fid,r,loc,false,post_analysis);
                        }
                        delete(e);
                    }
                }
            }
            //Now do the actual work to retrieve the TFs.
            FieldTaint *ft = host->getFieldTaint(fid);
            if (!ft || ft->empty()) {
                ft = &(host->all_contents_taint_flags);
            }
            if (!ft->empty()) {
                if (post_analysis) {
                    ft->doGetTf(loc,r,false);
                }else {
                    ft->getTf(loc,r);
                }
            }
            return;
        }

        //Get the winner TFs of a certain field.
        void getWinnerTfs(long fid, std::set<TaintFlag*> &r, bool get_eqv = true) {
            if (get_eqv) {
                std::set<TypeField*> eqs;
                this->getEqvArrayElm(fid,eqs);
                if (eqs.size() > 1) {
                    for (TypeField *e : eqs) {
                        if (e->fid != fid || e->priv != this) {
#ifdef DEBUG_FETCH_FIELD_TAINT
                            dbgs() << "AliasObject::getWinnerTfs(): ~~>[EQV OBJ] " << (const void*)(e->priv) << "|" << e->fid << "\n";
#endif
                            ((AliasObject*)e->priv)->getWinnerTfs(e->fid,r,false);
                        }
                        delete(e);
                    }
                }
            }
            FieldTaint *ft = this->getFieldTaint(fid);
            if (ft) {
                ft->getWinners(r);
            }else if (!this->all_contents_taint_flags.empty()) {
                this->all_contents_taint_flags.getWinners(r);
            }
            return;
        }

        /***
         * Add provided taint flag to the object at the provided field.
         * @param srcfieldId field to which taint needs to be added.
         * @param targetTaintFlag TaintFlag which needs to be added to the
         *                         provided field.
         * @return true if added else false if the taint flag is a duplicate.
         */
        bool addFieldTaintFlag(long srcfieldId, TaintFlag *targetTaintFlag, bool resolve_emb = false) {
            if (!targetTaintFlag) {
                return false;
            }
            AliasObject *host = this;
            //A special check for uncertain array element: don't propagate TFs originating from other elements in the same array
            //to the "-1" (uncertain) element, otherwise, every elem will point to every each other.
            //TODO: take care of layered arrays and equivalent fields.
            if (srcfieldId == -1 && targetTaintFlag->tag && targetTaintFlag->tag->priv == host) {
#ifdef DEBUG_UPDATE_FIELD_TAINT
                dbgs() << "AliasObject::addFieldTaintFlag(): reject adding TFs from other elements to the -1 element within the same array!\n";
#endif
                return false;
            }
            //If required, take care of the potential emb obj at the specified "fid".
            if (resolve_emb) {
                host = this->getNestedObj(srcfieldId,nullptr,targetTaintFlag->targetInstr);
                if (!host) {
                    host = this;
                }
                if (host != this) {
                    //This means what we need to set is in an embedded field obj at the original "srcfieldId", 
                    //so what we should propagate taint to is the field "0" of the emb "host".
                    srcfieldId = 0;
                }
            }
#ifdef DEBUG_UPDATE_FIELD_TAINT
            dbgs() << "AliasObject::addFieldTaintFlag(): " << InstructionUtils::getTypeName(host->targetType) 
            << " | " << srcfieldId << " obj: " << (const void*)host << "\n";
#endif
            FieldTaint *targetFieldTaint = host->getFieldTaint(srcfieldId);
            //Don't propagate a taint kill to a field which has not been tainted so far...
            if (!targetTaintFlag->is_tainted && (!targetFieldTaint || targetFieldTaint->empty())) {
#ifdef DEBUG_UPDATE_FIELD_TAINT
                dbgs() << "AliasObject::addFieldTaintFlag(): try to add a taint kill flag, but the target\
                field hasn't been tainted yet, so no action...\n";
#endif
                return false;
            }
            if (targetFieldTaint == nullptr) {
                targetFieldTaint = new FieldTaint(srcfieldId,host);
                host->taintedFields.push_back(targetFieldTaint);
            }
            return targetFieldTaint->addTf(targetTaintFlag);
        }

        //This is just a wrapper for convenience and compatibility.
        bool addAllContentTaintFlag(TaintFlag *tf) {
            if (!tf) {
                return false;
            }
            return this->all_contents_taint_flags.addTf(tf);
        }

        /***
         * Add provided taint to all the fields of this object.
         * @param targetTaintFlag TaintFlag that need to be added to all the fields.
         *
         * @return true if added else false if the taint flag is a duplicate.
         */
        bool taintAllFields(TaintFlag *targetTaintFlag) {
            if (this->addAllContentTaintFlag(targetTaintFlag)) {
                std::set<long> allAvailableFields = getAllAvailableFields();
                // add the taint to all available fields.
                for (auto fieldId : allAvailableFields) {
#ifdef DEBUG_UPDATE_FIELD_TAINT
                    dbgs() << "AliasObject::taintAllFields(): Adding taint to field:" << fieldId << "\n";
#endif
                    this->addFieldTaintFlag(fieldId, targetTaintFlag);
                }
                return true;
            }
            return false;
        }

        inline Value *getValue();

        inline void setValue(Value*);

        virtual void taintPointeeObj(AliasObject *newObj, long srcfieldId, InstLoc *targetInstr);

        virtual void fetchPointsToObjects(long srcfieldId, std::set<ObjectPointsTo*> &rptos, InstLoc *currInst = nullptr,
                                          bool get_eqv = true, bool create_obj = true);

        virtual void getEqvArrayElm(long fid, std::set<TypeField*> &res);

        virtual void createFieldPointee(long fid, std::set<ObjectPointsTo*> &rptos, 
                                        InstLoc *currInst = nullptr, InstLoc *siteInst = nullptr);

        virtual void logFieldAccess(long srcfieldId, Instruction *targetInstr = nullptr, const std::string &msg = "");

        //hz: A helper method to create and (taint) an embedded struct obj in the host obj.
        //If not null, "v" is the pointer to the created embedded object, "loc" is the creation site.
        AliasObject *createEmbObj(long fid, Value *v = nullptr, InstLoc *loc = nullptr);

        //Given a embedded object ("this") and its #field within the host object, and the host type, create the host object
        //and maintain their embedding relationships preperly.
        //"loc" is the creation site.
        AliasObject *createHostObj(Type *hostTy, long field, InstLoc *loc = nullptr);

        AliasObject *getNestedObj(long fid, Type *dty = nullptr, InstLoc *loc = nullptr);

        //Get the living field ptos at a certain InstLoc.
        virtual void getLivePtos(long fid, InstLoc *loc, std::set<ObjectPointsTo*> *retPto);

        //Reset the field pto records when switching to a new entry function.
        virtual void resetPtos(long fid, Instruction *entry);

        //Set this object as a taint source, i.e., attach an inherent taint tag and flag for each field.
        //The "loc" should usually be the creation site of "this" object.
        bool setAsTaintSrc(InstLoc *loc, bool is_global = true) {
#ifdef DEBUG_UPDATE_FIELD_TAINT
            dbgs() << "AliasObject::setAsTaintSrc(): set as taint src, obj: " << (const void*)this << "\n";
#endif
            Value *v = this->getValue();
            if (v == nullptr && this->targetType == nullptr) {
#ifdef DEBUG_UPDATE_FIELD_TAINT
                dbgs() << "AliasObject::setAsTaintSrc(): Neither Value nor Type information available for obj: " << (const void*)this << "\n";
#endif
                return false;
            }
            TaintTag *atag = nullptr;
            if (v) {
                atag = new TaintTag(-1,v,is_global,(void*)this);
            }else {
                atag = new TaintTag(-1,this->targetType,is_global,(void*)this);
            }
            //NOTE: inehrent TF is born w/ the object who might be accessed in different entry functions, so the "targetInstr" of its
            //inherent TF should be set to "nullptr" to indicate that it's effective globally from the very beginning, so that it can
            //also easily pass the taint path check when being propagated.
            //TODO: justify this decision.
            TaintFlag *atf = new TaintFlag(nullptr,true,atag);
            atf->is_inherent = true;
            if (this->addAllContentTaintFlag(atf)) {
                //add the taint to all available fields.
                std::set<long> allAvailableFields = this->getAllAvailableFields();
#ifdef DEBUG_UPDATE_FIELD_TAINT
                dbgs() << "AliasObject::setAsTaintSrc(): Updating field taint for obj: " << (const void*)this << "\n";
#endif
                for (auto fieldId : allAvailableFields) {
#ifdef DEBUG_UPDATE_FIELD_TAINT
                    dbgs() << "AliasObject::setAsTaintSrc(): Adding taint to: " << (const void*)this << " | " << fieldId << "\n";
#endif
                    TaintTag *tag = nullptr;
                    if (v) {
                        tag = new TaintTag(fieldId,v,is_global,(void*)this);
                    }else {
                        tag = new TaintTag(fieldId,this->targetType,is_global,(void*)this);
                    }
                    //We're sure that we want to set "this" object as the taint source, so it's a strong TF.
                    TaintFlag *newFlag = new TaintFlag(nullptr,true,tag);
                    newFlag->is_inherent = true;
                    this->addFieldTaintFlag(fieldId, newFlag);
                }
                this->is_taint_src = (is_global ? 1 : -1);
                return true;
            }
            return false;
        }

        //Clear all inherent TFs.
        void clearAllInhTFs() {
            this->all_contents_taint_flags.removeInhTFs();
            for (FieldTaint *ft : this->taintedFields) {
                if (ft) {
                    ft->removeInhTFs();
                }
            }
        }

        //In some situations we need to reset this AliasObject, e.g. the obj is originally 
        //allocated by kmalloc() w/ a type i8, and then converted to a composite type.
        //NOTE that this is usually for the conversion from non-composite obj to the composite one,
        //if current obj is already composite, we can create the host obj instead.
        void reset(Value *v, Type *ty, InstLoc *loc = nullptr) {
#ifdef DEBUG_OBJ_RESET
            dbgs() << "AliasObject::reset(): reset obj " << (const void*)this << " to type: " 
            << InstructionUtils::getTypeName(ty) << ", v: " << InstructionUtils::getValueStr(v) << "\n";
#endif
            std::set<long> oldFields = this->getAllAvailableFields();
            //Is this "setValue()" necessary and correct?
            //this->setValue(v);
            if (v && v->getType() && !ty) {
                ty = v->getType();
                if (ty->isPointerTy()) {
                    ty = ty->getPointerElementType();
                }
            }
            this->targetType = ty;
            std::set<long> curFields = this->getAllAvailableFields();
            std::set<long> addFields, delFields;
            for (auto id : curFields) {
                if (oldFields.find(id) == oldFields.end()) {
                    addFields.insert(id);
                }
            }
            for (auto id : oldFields) {
                if (curFields.find(id) == curFields.end()) {
                    delFields.insert(id);
                }
            }
            //Sync the "all_contents_taint_flags" w/ the newly available individual fields.
            //TODO: if "all_contents_taint_flags" is inherent, then we need to create different tags for each new field and set
            //individual inherent tag.
            /*
            if (addFields.size() && !this->all_contents_taint_flags.empty()) {
                std::set<TaintFlag*> all_tfs;
                this->all_contents_taint_flags.getTf(loc,all_tfs);
                if (all_tfs.empty()) {
                    return;
                }
#ifdef DEBUG_UPDATE_FIELD_TAINT
                dbgs() << "AliasObject::reset(): re-sync the all_contents_taint_flags to each field in reset obj: " << (const void*)this << "\n";
#endif
                for (auto fieldId : addFields) {
                    for (TaintFlag *tf : all_tfs) {
#ifdef DEBUG_UPDATE_FIELD_TAINT
                        dbgs() << "AliasObject::reset(): Adding taint to: " << (const void*)this << " | " << fieldId << "\n";
#endif
                        //NOTE: we just inherite the "is_weak" of the previousn TF here.
                        TaintFlag *ntf = new TaintFlag(tf, loc);
                        this->addFieldTaintFlag(fieldId, ntf);
                    }
                }
            }
            */
            if (delFields.size()) {
                //TODO: In theory we need to delete the field pto and TFs of these missing fields.
#ifdef DEBUG_UPDATE_FIELD_TAINT
                dbgs() << "!!! AliasObject::reset(): there are some deleted fields after reset!\n";
#endif
            }
        }

        std::set<long> getAllAvailableFields() {
            std::set<long> allAvailableFields;
            Type *ty = this->targetType;
            if (ty) {
                if (ty->isPointerTy()) {
                    ty = ty->getPointerElementType();
                }
                uint64_t seq_len;
                if (ty->isStructTy()) {
                    for (long i = 0; i < ty->getStructNumElements(); ++i) {
                        allAvailableFields.insert(i);
                    }
                    return allAvailableFields;
                } else if (InstructionUtils::isSeqTy(ty, nullptr, &seq_len)) {
                    for (long i = 0; i < seq_len; ++i) {
                        allAvailableFields.insert(i);
                    }
                    return allAvailableFields;
                }
            }
            if (this->pointsTo.size()) {
                // has some points to?
                // iterate thru pointsTo and get all fields.
                for (auto &x : this->pointsTo) {
                    if (x.second.size()) {
                        allAvailableFields.insert(x.first);
                    }
                }
            }else {
                // This must be a scalar type, or null type info.
                // just add taint to the field 0.
                allAvailableFields.insert(0);
            }
            return allAvailableFields;
        }

        //TaintInfo helpers end

        //We just created a new pointee object for a certain field in this host object, at this point
        //we may still need to handle some special cases, e.g.
        //(0) This host object A is a "list_head" (i.e. a kernel linked list node) and we created a new "list_head" B pointed to by
        //the A->next, in this case we also need to set B->prev to A.
        //(1) TODO: handle more special cases.
        int handleSpecialFieldPointTo(AliasObject *pobj, long fid, InstLoc *targetInstr) {
            if (!pobj) {
                return 0;
            }
            Type *ht = this->targetType;
            Type *pt = pobj->targetType;
            if (!ht || !pt || !ht->isStructTy() || !pt->isStructTy() || !InstructionUtils::same_types(ht,pt)) {
#ifdef DEBUG_SPECIAL_FIELD_POINTTO
                dbgs() << "AliasObject::handleSpecialFieldPointTo(): ht and pt are not the same struct pointer.\n";
#endif
                return 0;
            }
            //Is it of the type "list_head"?
            std::string ty_name = ht->getStructName().str();
#ifdef DEBUG_SPECIAL_FIELD_POINTTO
            dbgs() << "AliasObject::handleSpecialFieldPointTo(): type name: " << ty_name << "\n";
#endif
            if (ty_name.find("struct.list_head") == 0 && fid >= 0 && fid <= 1) {
#ifdef DEBUG_SPECIAL_FIELD_POINTTO
                dbgs() << "AliasObject::handleSpecialFieldPointTo(): Handle the list_head case: set the prev and next properly..\n";
                dbgs() << "AliasObject::handleSpecialFieldPointTo(): hobj: " << (const void*)this 
                << " pobj: " << (const void*)pobj << " fid: " << fid << "\n";
#endif
                pobj->addObjectToFieldPointsTo(1-fid,this,targetInstr,false);
                return 1;
            }
            return 0;
        }

        virtual AliasObject* makeCopy() {
            return new AliasObject(this);
        }

        virtual Value* getObjectPtr() {
            return nullptr;
        }

        virtual bool isSameObject(AliasObject *other) {
            return this == other;
        }

        virtual Value *getAllocSize() {
            return nullptr;
        }

        virtual InstLoc *getAllocLoc() {
            return nullptr;
        }

        virtual int64_t getTypeAllocSize(DataLayout *targetDL) {
            // if there is no type or this is a void*, then we do not know the alloc size.
            if(targetType == nullptr ||
                    (targetType->isPointerTy() &&
                                         targetType->getContainedType(0)->isIntegerTy(8)) ||
                    (!targetType->isSized())) {
                return -1;
            }
            return targetDL->getTypeAllocSize(targetType);
        }

        friend llvm::raw_ostream& operator<<(llvm::raw_ostream& os, const AliasObject& obj) {
            os << "Object with type:";
            obj.targetType->print(os);
            os <<" ID:" << &(obj) << "\n";
            obj.printPointsTo(os);
            return os;
        }

        virtual bool isFunctionArg() {
            /***
             * checks whether the current object is a function argument.
             */
            return false;
        }

        virtual bool isFunctionLocal() {
            /***
             * checks whether the current object is a function local object.
             */
            return false;
        }

        virtual bool isHeapObject() {
            /***
             * Returns True if this object is a malloced Heap object.
             */
            return false;
        }

        virtual bool isHeapLocation() {
            /***
             * Returns True if this object is a HeapLocation instance.
             */
            return false;
        }

        virtual bool isGlobalObject() {
            /***
             * Returns True if this object is a Global object.
             */
            return false;
        }

        //hz: add for new subclass.
        virtual bool isOutsideObject() {
            /***
             * Returns True if this object is an Outside object.
             */
            return false;
        }

        //hz: return true if this is a placeholder dummy object.
        virtual bool isDummy() {
            return (this->isOutsideObject() || this->auto_generated);
        }

        virtual long getArraySize() {
            /***
             *  Returns array size, if this is array object.
             *  else returns -1
             */
             if(this->targetType != nullptr && this->targetType->isArrayTy()) {
                 return this->targetType->getArrayNumElements();
             }
            return -1;
        }

        //NOTE: "is_weak" by default is "-1", this means whether it's a weak update is 
        //decided by "is_weak" field of each PointerPointsTo in "dstPointsTo",
        //in some cases, the arg "is_weak" can be set to 0 (strong update) or 1 (weak update) 
        //to override the "is_weak" field in "dstPointsTo".
        //NOTE: this function will make a copy of "dstPointsTo" and will not do any modifications 
        //to "dstPointsTo", the caller is responsible to free "dstPointsTo" if necessary.
        void updateFieldPointsTo(long srcfieldId, std::set<ObjectPointsTo*> *dstPointsTo,
                                 InstLoc *propagatingInstr, int is_weak = -1,
                                 std::set<ObjectPointsTo*> *fptos = nullptr);

        //A wrapper for compatiability...
        //TODO: this ugly, need to refactor later.
        void updateFieldPointsTo(long srcfieldId, std::set<PointerPointsTo*> *dstPointsTo,
                                 InstLoc *propagatingInstr, int is_weak = -1,
                                 std::set<ObjectPointsTo*> *fptos = nullptr) {
            if (!dstPointsTo || dstPointsTo->empty()) {
                return;
            }
            std::set<ObjectPointsTo*> ptos;
            for (PointerPointsTo *p : *dstPointsTo) {
                ptos.insert(p);
            }
            this->updateFieldPointsTo(srcfieldId,&ptos,propagatingInstr,is_weak,fptos);
        }

        FieldTaint* getFieldTaint(long srcfieldId) {
            for(auto currFieldTaint : taintedFields) {
                if(currFieldTaint->fieldId == srcfieldId) {
                    return currFieldTaint;
                }
            }
            return nullptr;
        }

    private:

        //NOTE: the arg "is_weak" has the same usage as updateFieldPointsTo().
        void updateFieldPointsTo_do(long srcfieldId, std::set<ObjectPointsTo*> *dstPointsTo,
                                    InstLoc *propagatingInstr, int is_weak = -1,
                                    std::set<ObjectPointsTo*> *fptos = nullptr);

        //This records the first inst of an entry function we have just swicthed to and reset the field (key is the field ID) pto.
        std::map<long,Instruction*> lastPtoReset;

    protected:
        void printPointsTo(llvm::raw_ostream& os) const {
            os << "Points To Information:\n";
            for (auto &x : this->pointsTo) {
                os << "Field: " << x.first << ":\n";
                for (ObjectPointsTo *obp : x.second) {
                    os << "\t" << (*obp) << "\n";
                }
            }
        }
    };

    class FunctionLocalVariable : public AliasObject {
    public:
        Function *targetFunction = nullptr;
        InstLoc *targetAllocaInst = nullptr;

        FunctionLocalVariable(InstLoc *targetInst) {
            this->targetAllocaInst = targetInst;
            if (targetInst) {
                this->targetFunction = targetInst->getFunc();
            }
            if (dyn_cast<AllocaInst>(targetInst->inst)) {
                this->targetType = dyn_cast<AllocaInst>(targetInst->inst)->getAllocatedType();
            }
            if(this->targetType && this->targetType->isStructTy()) {
                this->is_initialized = false;
                this->initializingInstructions.clear();
            }
        }

        FunctionLocalVariable(FunctionLocalVariable *srcLocalVariable): AliasObject(srcLocalVariable) {
            this->targetFunction = srcLocalVariable->targetFunction;
            this->targetAllocaInst = srcLocalVariable->targetAllocaInst;
            this->targetType = srcLocalVariable->targetType;
        }

        AliasObject* makeCopy() {
            return new FunctionLocalVariable(this);
        }

        Value* getObjectPtr() {
            if (this->targetAllocaInst) {
                return this->targetAllocaInst->inst;
            }
            return nullptr;
        }

        bool isFunctionLocal() {
            return true;
        }

        friend llvm::raw_ostream& operator<<(llvm::raw_ostream& os, const FunctionLocalVariable& obj) {
            os << "Function Local variable with type: "
            << InstructionUtils::getTypeName(obj.targetType) << " ID: " << obj.id << "\n";
            obj.printPointsTo(os);
            return os;
        }
    };

    class GlobalObject : public AliasObject {
    public:
        Value *targetVar;
        GlobalObject(llvm::GlobalVariable *globalDef, Type *globVarType) {
            this->targetVar = (Value*)globalDef;
            this->targetType = globVarType;
        }
        GlobalObject(Value* globalVal, Type *globVarType) {
            this->targetVar = globalVal;
            this->targetType = globVarType;
        }
        GlobalObject(Function *targetFunction) {
            this->targetVar = targetFunction;
            this->targetType = targetFunction->getType();
        }
        GlobalObject(GlobalObject *origGlobVar): AliasObject(origGlobVar) {
            this->targetVar = origGlobVar->targetVar;
            this->targetType = origGlobVar->targetType;
        }
        AliasObject* makeCopy() {
            return new GlobalObject(this);
        }
        Value* getObjectPtr() {
            return this->targetVar;
        }

        bool isGlobalObject() {
            return true;
        }
    };

    //hz: create a new GlobalObject for a pointer Value w/o point-to information, this
    //can be used for driver function argument like FILE * which is defined outside the driver module.
    class OutsideObject : public AliasObject {
    public:
        //hz: the pointer to the outside object.
        Value *targetVar;
        OutsideObject(Value* outVal, Type *outVarType) {
            this->targetVar = outVal;
            this->targetType = outVarType;
#ifdef DEBUG_OUTSIDE_OBJ_CREATION
            dbgs() << "###NEW OutsideObj: targetVar: " << InstructionUtils::getValueStr(this->targetVar) 
            << " ty: " << InstructionUtils::getTypeName(this->targetType) << "\n";
#endif
        }
        OutsideObject(OutsideObject *origOutsideVar): AliasObject(origOutsideVar) {
            this->targetVar = origOutsideVar->targetVar;
            this->targetType = origOutsideVar->targetType;
#ifdef DEBUG_OUTSIDE_OBJ_CREATION
            dbgs() << "###COPY OutsideObj: targetVar: " << InstructionUtils::getValueStr(this->targetVar) 
            << " ty: " << InstructionUtils::getTypeName(this->targetType) << "\n";
#endif
        }
        AliasObject* makeCopy() {
            return new OutsideObject(this);
        }

        Value* getObjectPtr() {
            return this->targetVar;
        }

        bool isOutsideObject() {
            return true;
        }

    };

    class HeapLocation : public AliasObject {
    public:
        Function *targetFunction = nullptr;
        InstLoc *allocLoc = nullptr;
        Value *targetAllocSize = nullptr;
        bool is_malloced = false;

        HeapLocation(InstLoc *allocLoc, Type* targetType,
                     Value *allocSize, bool is_malloced) {
            this->allocLoc = allocLoc;
            this->targetType = targetType;
            this->targetFunction = (allocLoc ? allocLoc->getFunc() : nullptr);
            this->targetAllocSize = allocSize;
            this->is_malloced = is_malloced;
            this->is_initialized = false;
            this->initializingInstructions.clear();
        }

        HeapLocation(Type* targetType, Value *allocSize, bool is_malloced) {
            this->targetType = targetType;
            this->targetFunction = nullptr;
            this->targetAllocSize = allocSize;
            this->is_malloced = is_malloced;
            this->is_initialized = false;
            this->initializingInstructions.clear();
        }

        HeapLocation(HeapLocation *srcHeapLocation): AliasObject(srcHeapLocation) {
            this->targetFunction = srcHeapLocation->targetFunction;
            this->targetType = srcHeapLocation->targetType;
            this->allocLoc = srcHeapLocation->allocLoc;
            this->targetAllocSize = srcHeapLocation->targetAllocSize;
            this->is_malloced = srcHeapLocation->is_malloced;
        }

        AliasObject* makeCopy() {
            return new HeapLocation(this);
        }

        Value* getObjectPtr() {
            if (this->allocLoc) {
                return this->allocLoc->inst;
            }
            return nullptr;
        }

        Value* getAllocSize() {
            return this->targetAllocSize;
        }

        InstLoc *getAllocLoc() {
            return this->allocLoc;
        }

        bool isHeapObject() {
            /***
             * Return true if this is malloced
             */
            return this->is_malloced;
        }

        bool isHeapLocation() {
            return true;
        }

    };

    class FunctionArgument : public AliasObject {
    public:
        InstLoc *argLoc;
        // TODO: handle pointer args
        FunctionArgument(InstLoc *argLoc, Type* targetType) {
            this->argLoc = argLoc;
            this->targetType = targetType;
        }
        FunctionArgument(FunctionArgument *srcFunctionArg) : AliasObject(srcFunctionArg) {
            this->argLoc = srcFunctionArg->argLoc;
            this->targetType = srcFunctionArg->targetType;
        }

        AliasObject* makeCopy() {
            return new FunctionArgument(this);
        }

        Value* getObjectPtr() {
            if (this->argLoc) {
                return this->argLoc->inst;
            }
            return nullptr;
        }

        bool isFunctionArg() {
            return true;
        }
    };

    //hz: get the llvm::Value behind this AliasObject.
    Value *AliasObject::getValue() {
        return this->getObjectPtr();
        /*
        Value *v = nullptr;
        if (this->isGlobalObject()){
            v = ((DRCHECKER::GlobalObject*)this)->targetVar;
        }else if(this->isFunctionArg()){
            v = ((DRCHECKER::FunctionArgument*)this)->targetArgument;
        }else if (this->isFunctionLocal()){
            v = ((DRCHECKER::FunctionLocalVariable*)this)->targetVar;
        }else if (this->isOutsideObject()){
            v = ((DRCHECKER::OutsideObject*)this)->targetVar;
        }//TODO: HeapAllocation
        return v;
        */
    }

    //hz: A helper method to create a new OutsideObject according to a given type.
    //Note that all we need is the type, in the program there may not exist any IR that can actually point to the newly created object,
    //thus this method is basically for the internal use (e.g. in multi-dimension GEP, or in fetchPointToObjects()).
    extern OutsideObject* createOutsideObj(Type *ty);

    //hz: A helper method to create a new OutsideObject according to the given pointer "p" (possibly an IR).
    //"loc" is the creation site.
    extern OutsideObject* createOutsideObj(Value *p, InstLoc *loc = nullptr);

    extern int matchFieldsInDesc(Module *mod, Type *ty0, std::string& n0, Type *ty1, std::string& n1, 
                                 int bitoff, std::vector<FieldDesc*> *fds, std::vector<unsigned> *res);

    extern void sortCandStruct(std::vector<CandStructInf*> *cands, std::set<Instruction*> *insts);

    //Given 2 field types and their distance (in bits), return a list of candidate struct types.
    extern std::vector<CandStructInf*> *getStructFrom2Fields(DataLayout *dl, Type *ty0, std::string& n0, 
                                                             Type *ty1, std::string& n1, long bitoff, Module *mod);

    //This function assumes that "v" is a i8* srcPointer of a single-index GEP and it points to the "bitoff" inside an object of "ty",
    //our goal is to find out the possible container objects of the target object of "ty" (the single-index GEP aims to locate a field
    //that is possibly outside the scope of current "ty" so we need to know the container), to do this we will analyze all similar GEPs
    //that use the same "v" as the srcPointer.
    //Return: we return a "CandStructInf" to indicate the location of the original "bitoff" inside "ty" in the larger container object.
    extern CandStructInf *inferContainerTy(Module *m,Value *v,Type *ty,long bitoff);

    extern int addToSharedObjCache(AliasObject *obj);

    extern int getFromSharedObjCache(Type *ty, std::set<AliasObject*> &res);

    //"fd" is a bit offset desc of "pto->targetObject", it can reside in nested composite fields, 
    //this function creates all nested composite fields
    //in order to access the bit offset of "fd", while "limit" is the lowest index we try to create an emb obj in fd->host_tys[].
    extern int createEmbObjChain(FieldDesc *fd, PointerPointsTo *pto, int limit, InstLoc *loc = nullptr);

    extern int createHostObjChain(FieldDesc *fd, PointerPointsTo *pto, int limit, InstLoc *loc = nullptr);

}

#endif //PROJECT_ALIASOBJECT_H
