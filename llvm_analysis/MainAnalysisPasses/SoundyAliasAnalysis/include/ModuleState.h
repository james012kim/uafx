//
// Created by machiry on 10/25/16.
//

#ifndef PROJECT_MODULESTATE_H
#define PROJECT_MODULESTATE_H
#include "AliasObject.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "bug_detectors/warnings/VulnerabilityWarning.h"
#include <set>
#include <chrono>
#include <ctime>
#include <fstream>
#include <functional>
#include <memory>
#include "TaintInfo.h"
#include "../../Utils/include/CFGUtils.h"
#include "../../Utils/include/Constraint.h"
#include "../../Utils/include/LockInfo.h"
#include "Trait.h"

//#define DEBUG_HIERARCHY
#define PRINT_HIERARCHY_CHAIN
#define DEBUG_CONSTRUCT_TAINT_CHAIN
#define CONFINE_RECUR_STRUCT
#define CALC_HIERARCHY_HASH
#define DEBUG_FP_FILTERING
#define DEBUG_ADD_SUPP_LOC
#define DEBUG_CALLBACK_ANALYSIS

using namespace llvm;

namespace DRCHECKER {
//#define DEBUG_GLOBALS

    class Thread;
    class InstLocTr;
    class ThreadSched;
    class GlobalState;

  //A wrapper of InstLoc that stores more info for FP warning filtering purpose.
    class InstLocTr {
    public:
        //Define some types of InstLoc.
        static const int TY_DEF = 0;
        static const int TY_FREE = 1 << 0;
        static const int TY_USE = 1 << 1;
        static const int TY_LOCK = 1 << 2;
        static const int TY_UNLOCK = 1 << 3;
        static const int TY_GSET = 1 << 4;
        static const int TY_GCHECK = 1 << 5;
        static const int TY_ESCAPE = 1 << 6;
        static const int TY_FETCH = 1 << 7;
        static const int TY_TR_CREATE = 1 << 8;
        static const int TY_TR_JOIN = 1 << 9;
        static const int TY_ALL = ~0;
        //////////////////////////////
        InstLoc *loc;
        //One difference between InstLocTr and InstLoc is that the former is one node
        //in an execution flow - besides the mere location (InstLoc), it's also
        //associated with concerete data flow info (e.g., which pto is used at this
        //location in this specific execution flow).
        //"ptos" include such pto info for each operand in loc->inst. 
        std::map<Value*,std::set<PointerPointsTo*>> ptos;
        //The thread this inst loc belongs to, note that a same InstLocTr instance can belong
        //to multiple Threads - each in a different ThreadSched, this is mainly to support
        //the ThreadSched forking mechanism - we may need to explore alternative sched
        //for the feasibility of the bug.
        std::map<ThreadSched*, Thread*> tr;
        //The type of this InstLoc.
        int ty;
        InstLocTr(ThreadSched *trs, Thread *tr, InstLoc *loc, int ty = InstLocTr::TY_DEF) {
            this->loc = loc;
            this->tr[trs] = tr;
            this->ty = ty;
        }
        InstLocTr(): InstLocTr(nullptr, nullptr, nullptr) {}

        Thread *getTr(ThreadSched *trs) {
            if (this->tr.find(trs) != this->tr.end()) {
                return this->tr[trs];
            }
            return nullptr;
        }

        void setTr(ThreadSched *trs, Thread *tr) {
            this->tr[trs] = tr;
            return;
        }

        void addPto(Value *v, PointerPointsTo *pto) {
            if (!v || !pto || !this->loc || !this->loc->inst) {
                return;
            }
            //Ensure that "v" is one operand of loc->inst.
            std::set<Value*> vs;
            InstructionUtils::getInvolvedValues(this->loc->inst,vs,true);
            if (vs.find(v) == vs.end()) {
                return;
            }
            //Insert the pto, we assume the passed in "pto" is a subset of the points-to
            //analysis results, which has already been de-duplicated.
            this->ptos[v].insert(pto);
        }

        void addPtos(std::set<PointerPointsTo*> *ptos) {
            if (!ptos || ptos->empty()) {
                return;
            }
            for (PointerPointsTo *pto : *ptos) {
                if (!pto) continue;
                this->addPto(pto->targetPointer,pto);
            }
            return;
        }

        void print(raw_ostream &O, bool lbreak = true) {
            O << "loc: ";
            if (loc)
                loc->print_light(O, false);
            else
                O << "null";
            O << ", ty: " << this->getTyName();
            if (lbreak)
                O << "\n";
            return;
        }

    private:
        std::string getTyName() {
            static std::string tyName[] = {
                "TY_FREE",
                "TY_USE",
                "TY_LOCK",
                "TY_UNLOCK",
                "TY_GSET",
                "TY_GCHECK",
                "TY_ESCAPE",
                "TY_FETCH",
                "TY_TR_CREATE",
                "TY_TR_JOIN",
            };
            std::string ret;
            for (int i = 0; i < sizeof(tyName) / sizeof(tyName[0]); ++i) {
                if (this->ty & (1 << i)) {
                    ret += tyName[i] + "|";
                }
            }
            return ret;
        }
    };

    //Abstract a thread.
    class Thread {
    public:
        int id = -1;
        std::vector<std::shared_ptr<InstLocTr>> seq;
        class ThreadSched *sched = nullptr;
        Thread(int id, ThreadSched *sched): id(id), sched(sched) {}
        Thread(): Thread(-1, nullptr) {}

        void print(raw_ostream &O) {
            for (auto &tr: this->seq) {
                if (!tr) {
                    continue;
                }
                tr->print(O, true);
            }
        }

        //Fork a new thread for the alternative thread schedule "trs".
        Thread *fork(ThreadSched *trs) {
            Thread *ntr = new Thread(this->id, trs);
            for (auto &locTr : this->seq) {
                locTr->setTr(trs, ntr);
                ntr->seq.push_back(locTr);
            }
            return ntr;
        }

        //Insert a new InstLocTr to the thread.
        //Arg:
        //"loc": the InstLoc to be inserted.
        //"ty": the type of the InstLoc.
        //"stop_loc": if provided, we will only try to make the insertion before it.
        //"merge": if a same InstLoc alreadys exists in the thread, we will merge the types
        //if this flag is "true", otherwise, the insertion will fail.
        //"dom": if true, only insert the InstLoc if it dominates/post-dominates an existing
        //InstLoc in the thread.
        //"start_loc": the insertion must happen after the specified loc.
        //"dry_run": if true, do not actually insert the loc.
        //Ret:
        //The InstLocTr instance corresponding to the "loc" if intertion succeds,
        //otherwise nullptr.
        //Besides, if "ec" is not nullptr, we will record additional info in "*ec": 
        //(1) if a new InstLocTr is created for the "loc" -> its index (>= 0)
        //(2) insertion fails because of incompatiable reachability -> -1
        //(3) insertion fails because of a same InstLoc|type already exists -> -2
        //(4) type merged to existing InstLocTr -> -3
        //(5) insertion fails because of other errors -> -4
        //(6) insertion fails because "loc" is not inevitable for the thread but "dom"
        //is true -> -5
        //(7) insertion fails because "stop_loc" has been passed -> -6
        std::shared_ptr<InstLocTr> insertLoc(InstLoc *loc, int ty = InstLocTr::TY_DEF, 
                      bool merge = true, bool dom = false, int *ec = nullptr,
                      std::shared_ptr<InstLocTr> stop_loc = nullptr,
                      std::shared_ptr<InstLocTr> start_loc = nullptr,
                      bool dry_run = false) {
            int err = -4;
            std::shared_ptr<InstLocTr> locTr(nullptr);
            int stop_idx = this->seq.size();
            int start_idx = -1;
            if (!loc) {
                goto exit;
            }
            //Decide the end of the search range.
            if (stop_loc) {
                auto it = std::find(this->seq.begin(), this->seq.end(), stop_loc);
                assert(it != this->seq.end());
                stop_idx = it - this->seq.begin();
                ++stop_idx;
            }
            //Decide the start of the search range.
            if (start_loc) {
                auto it = std::find(this->seq.begin(), this->seq.end(), start_loc);
                assert(it != this->seq.end());
                start_idx = it - this->seq.begin();
                //Verify that start_loc (if specified) can reach "loc".
                if (!loc->reachable(this->seq[start_idx]->loc)) {
                    err = -6;
                    goto exit;
                }
            }
            //First of all search for any same InstLoc that is already presented in
            //the thread, if we don't do this first, since there can be loops, we
            //may end up with multiple identical InstLocs in the thread.
            for (int i = 0; i < this->seq.size(); ++i) {
                if (!this->seq[i] || (this->seq[i]->loc != loc)) {
                    continue;
                }
                // Same InstLoc presented in current thread.
                // If it already surpasses the "stop_loc": we wil exit directly,
                // though it's still possible to insert the same InstLoc before
                // the "stop_loc", that will result in duplicated InstLocs in
                // the thread, so we neither insert before, nor merge after.
                // The reasoning for "start_loc" is similar.
                if (i >= stop_idx || i <= start_idx) {
                    err = -6;
                    goto exit;
                }
                locTr = this->seq[i];
                if (locTr->ty & ty) {
                    // The same type also presents, no actions needed.
                    err = -2;
                } else if (merge) {
                    if (!dry_run) {
                        locTr->ty |= ty;
                    }
                    err = -3;
                } else {
                    // At this point, it must be that the caller refuses the type merge,
                    // we can only fail the insertion and return nullptr.
                    err = -4;
                    locTr = nullptr;
                }
                goto exit;
            }
            //No identical InstLoc found, try to find a slot for the insertion.
            for (int i = start_idx + 1; i < stop_idx; ++i) {
                //Try to insert the "loc" before the index "i".
                if (!this->seq[i] || !this->seq[i]->loc) {
                    continue;
                }
                //Ok, now test whether the "loc" can reach current node of index "i".
                if (!this->seq[i]->loc->reachable(loc)) {
                    if (loc->reachable(this->seq[i]->loc)) {
                        //"loc" should be inserted in later positions.
                        continue;
                    } else {
                        //"loc" cannot reach seq[i], if the latter cannot reach the former neither,
                        //we can directly conclude that "loc" is not compatiable with the thread.
                        locTr = nullptr;
                        err = -1;
                        goto exit;
                    }
                }
                //At this point, "loc" can reach seq[i], it's also guaranteed that seq[i-1] (if i > 0)
                //can also reach "loc" (in the last iteration), so we can insert "loc" here.
                //Check "dom" flag, baiscally, if "dom" is true, to insert "loc"
                //it must be ineviatable in this thread, there are several cases: 
                //(1) if i > 0, "loc" must be on every path from seq[i-1] to seq[i];
                //(2) if i == 0, "loc" must dominate seq[0];
                //(3) if i == seq.size() - 1, "loc" must post-dominate seq.back().
                bool insert = true;
                if (dom) {
                    if (i == 0 && !loc->dom(this->seq[0]->loc)) {
                        insert = false;
                    } else if (i > 0) {
                        std::set<InstLoc*> block{loc};
                        if (seq[i]->loc->reachable(seq[i-1]->loc, &block)) {
                            insert = false;
                        }
                    }
                }
                if (insert) {
                    if (!dry_run) {
                        locTr.reset(new InstLocTr(this->sched, this, loc, ty));
                        this->seq.insert(this->seq.begin() + i, locTr);
                    }
                    err = i;
                } else {
                    locTr = nullptr;
                    err = -5;
                }
                goto exit;
            }
            if (stop_loc) {
                //The user has specified a stop location limit, reaching here
                //means that we cannot insert "loc" before the stop location,
                //and it's also forbidden to insert "loc" after the stop location.
                locTr = nullptr;
                err = -6;
                goto exit;
            }
            //Reaching this point indicates that the "loc" can and should be
            //appended to the end of this thread, given that "dom" is honored.
            if (this->seq.empty() || !dom || loc->postDom(this->seq.back()->loc)) {
                if (!dry_run) {
                    locTr.reset(new InstLocTr(this->sched, this, loc, ty));
                    this->seq.push_back(locTr);
                    err = this->seq.size() - 1;
                } else {
                    //No real insertion, only update the "err" to indicate
                    //the insertion location.
                    //"err" should be >= 0 in this case, indicating success.
                    err = this->seq.size();
                }
            } else {
                locTr = nullptr;
                err = -5;
            }
exit:
            if (ec) {
                *ec = err;
            }
            return locTr;
        }

        //A wrapper to make things simple: just test whether we can
        //insert a InstLoc w/o actually doing it, return true if
        //feasible, false otherwise.
        bool testInsertLoc(InstLoc *loc, int ty = InstLocTr::TY_DEF, 
                           bool merge = true, bool dom = false,
                           std::shared_ptr<InstLocTr> stop_loc = nullptr,
                           std::shared_ptr<InstLocTr> start_loc = nullptr)
        {
            int ec = -1;
            this->insertLoc(loc,ty,merge,dom,&ec,stop_loc,start_loc,true);
            return (ec >= 0 || ec == -2 || ec == -3);
        }

        //Given a location in this thread, test whether it's still reachable
        //with a set of blockers (e.g., the path to/from it may be blocked).
        bool reachableWithBlockers(std::shared_ptr<InstLocTr> locTr,
                                   std::set<InstLoc*> &blockers) {
            if (!locTr || !locTr->loc) {
                return false;
            }
            auto it = std::find(this->seq.begin(), this->seq.end(), locTr);
            if (it == this->seq.end()) {
                return false;
            }
            int i = it - this->seq.begin();
            InstLoc *curr = locTr->loc;
            if (i > 0) {
                //Test the reachability from its predecessor.
                InstLoc *prev = this->seq[i-1]->loc;
                if (!prev || !curr->reachable(prev,&blockers)) {
                    return false;
                }
            }
            if (i < this->seq.size() - 1) {
                //Test the reachability to its successor.
                InstLoc *next = this->seq[i+1]->loc;
                if (!next || !next->reachable(curr,&blockers)) {
                    return false;
                }
            }
            return true;
        }

        //This is a wrapper for a simple compatiability test of
        //the "loc" in current sequence.
        //rpos:
        // -1: the "loc" should be inserted before the end of the sequence.
        //  1: after the beginning of the seq.
        //  0: can be inserted anywhere, as long as compatiable with the thread.
        //ret: true if the "loc" can satisfy the positioning requirements.
        bool testLocInSeq(InstLoc *loc, int rpos) {
            if (!loc) {
                return false;
            }
            int ec = 0;
            std::shared_ptr<InstLocTr> st = nullptr, ed = nullptr;
            if (rpos && !this->seq.empty()) {
                if (rpos > 0) {
                    st = this->getLoc(0);
                }
                if (rpos < 0) {
                    ed = this->getLoc(this->seq.size() - 1);
                }
            }
            std::shared_ptr<InstLocTr> locTr = this->insertLoc(loc,InstLocTr::TY_DEF,
                                                               true,false,&ec,ed,st);
            return (locTr != nullptr);
        }

        //Fill the thread with the provided InstLoc seq.
        //It's expected that "seq" is a valid execution trace.
        //Return 0 if no errors, otherwise negative values.
        int init(std::vector<InstLoc*> &locs) {
            if (locs.empty()) {
                return 0;
            }
            //Since "seq" is expected to be valid, reverse insertion can
            //optimize the efficiency.
            for (int i = locs.size() - 1; i >= 0; --i) {
                auto plocTr = this->insertLoc(locs[i]);
                if (!plocTr) {
                    // Init fails.
                    this->seq.clear();
                    return -1;
                }
            }
            return 0;
        }

        //Remove the specified InstLoc from the thread.
        //Ret:
        //>= 0: if the loc has multiple types and we just mask out one of them
        //instead of erasing the whole loc, return the index of the loc.
        //-1: the loc has been removed
        //-2: the loc doesn't exist in the thread
        //-3: other errors
        int removeLoc(InstLoc *loc, int ty = InstLocTr::TY_ALL) {
            if (!loc) {
                return -3;
            }
            for (unsigned i = 0; i < this->seq.size(); ++i) {
                if (!this->seq[i] || !this->seq[i]->loc) {
                    continue;
                }
                if (this->seq[i]->loc == loc) {
                    this->seq[i]->ty &= ~ty;
                    if (this->seq[i]->ty == 0) {
                        //We are smart now!
                        //delete this->seq[i];
                        this->seq.erase(this->seq.begin() + i);
                        return -1;
                    }
                    return i;
                }
            }
            return -2;
        }

        //Basically the same as the above overloaded version, but just with a different arg
        //type for convenience.
        int removeLoc(std::shared_ptr<InstLocTr> locTr, int ty = InstLocTr::TY_ALL) {
            if (!locTr) {
                return -3;
            }
            auto it = std::find(this->seq.begin(), this->seq.end(), locTr);
            if (it == this->seq.end()) {
                return -2;
            }
            int i = it - this->seq.begin();
            locTr->ty &= ~ty;
            if (locTr->ty == 0) {
                this->seq.erase(it);
                //Smart now!
                //delete locTr;
                return -1;
            }
            return i;
        }

        //Retrieve a specific InstLocTr from the thread.
        std::shared_ptr<InstLocTr> getLoc(int idx) {
            if (idx < 0 || idx >= this->seq.size()) {
                return nullptr;
            }
            return this->seq[idx];
        }

        std::shared_ptr<InstLocTr> getLoc(InstLoc *loc) {
            if (!loc) {
                return nullptr;
            }
            for (auto &tr: this->seq) {
                if (tr && tr->loc == loc) {
                    return tr;
                }
            }
            return nullptr;
        }

        Function *getEntryFunc() {
            auto locTr = this->getLoc(0);
            if (!locTr || !locTr->loc) {
                return nullptr;
            }
            return locTr->loc->getEntryFunc();
        }
    };

    //Abstratcs a shcedule of threads to trigger the vulnerability.
    class ThreadSched {
    public:
        //We need the GlobalState to be able to get esential schedule related info.
        GlobalState *gs = nullptr;
        //The list of threads.
        std::vector<Thread*> trs;
        //Two key InstLoc composing this bug, U/F or F/F.
        std::shared_ptr<InstLocTr> locTr0, locTr1;
        //Hold the lock info for all newly inserted lock/unlock InstLocs.
        std::map<LockInfo*, std::set<std::pair<std::shared_ptr<InstLocTr>, std::shared_ptr<InstLocTr>>>> lockMap;
        //Partial-Order constarint manager for this schedule.
        POConstraint *poc = nullptr;
        //Alternate thread schedule to trigger the UAF (e.g., maybe we have one lock but two
        //corresponding unlocks in two branches afterwards, so we may beed to explore both ones).
        std::set<ThreadSched*> altScheds;

        ThreadSched(GlobalState *gs) {
            assert(gs);
            this->gs = gs;
            this->poc = new POConstraint();
        }

        ~ThreadSched() {
            for (ThreadSched *trs : this->altScheds) {
                delete trs;
            }
            for (auto tr: this->trs) {
                delete tr;
            }
            delete this->poc;
        }

    private:
        //Null constructor, only for internal use.
        ThreadSched() {};

        int _setLocTrPtos(std::shared_ptr<InstLocTr> locTr, AliasObject *obj) {
            if (!obj || !locTr || !locTr->loc) {
                return -1;
            }
            InstLoc *loc = locTr->loc;
            if (locTr->ty == InstLocTr::TY_FREE) {
                std::set<PointerPointsTo*> *ptos = obj->getFreePtos(loc);
                locTr->addPtos(ptos);
            } else if (locTr->ty == InstLocTr::TY_USE) {
                std::set<PointerPointsTo*> ptos;
                obj->getUsePtos(loc, ptos);
                locTr->addPtos(&ptos);
            }
            return 0;
        }

    public:
        //Clone the current schedule as the basis for an alterntive one.
        ThreadSched *fork() {
            ThreadSched *ntrs = new ThreadSched();
            ntrs->gs = this->gs;
            //Fork the threads.
            for (Thread *tr : this->trs) {
                ntrs->trs.push_back(tr->fork(ntrs));
            }
            ntrs->locTr0 = this->locTr0;
            ntrs->locTr1 = this->locTr1;
            ntrs->lockMap = this->lockMap;
            //Clone the POConstraint.
            ntrs->poc = this->poc->fork();
            this->altScheds.insert(ntrs);
            return ntrs;
        }

        //Print out the details of this thread schedule, including each thread and
        //its contained InstLocs.
        void print(raw_ostream &O) {
            O << "<<<<<<<Begin ThreadSched(" << (const void*)this << ")>>>>>>>\n";
            for (unsigned i = 0; i < this->trs.size(); ++i) {
                O << "Thread " << i << ":\n";
                this->trs[i]->print(O);
            }
            O << "<<<<<<<End ThreadSched(" << (const void*)this << ")>>>>>>>\n";
            return;
        }

        //Create one or two threads to trigger the UAF style bugs, depending one the
        //relationship of the two InstLocs (e.g., U/F or F/F).
        int initUAFThreads(InstLoc *loc0, AliasObject *obj0, int ty0,
                           InstLoc *loc1, AliasObject *obj1, int ty1) {
            if (!loc0 || !loc1) {
                return -1;
            }
            this->locTr0 = this->initThread(loc0, ty0);
            if (!this->locTr0) {
                //This should be impossible.
                return -1;
            }
            Thread *tr0 = this->locTr0->getTr(this);
            assert(tr0);
            bool is_021 = loc1->reachable(loc0);
            if (is_021) {
                //loc0 can reach loc1, so assign them to a single thread.
                int ec = -1;
                this->locTr1 = tr0->insertLoc(loc1,ty1,true,false,&ec);
                //TODO: according to current implementation of "insertLoc", if
                //F and U are in a loop (e.g., mutually rechable), the condition
                //below will be evaluated to false. Since this likely results
                //to a FP.
                if (ec != 1) {
                    //This should be impossible.
                    return -1;
                }
            } else {
                //F and U need to be triggered in different threads.
                this->locTr1 = this->initThread(loc1,ty1);
            }
            if (!this->locTr1) {
                //This should be impossible.
                return -1;
            }
            //Both locs are successfully inserted, now setup their pto records to
            //the relevant objs.
            this->_setLocTrPtos(this->locTr0,obj0);
            this->_setLocTrPtos(this->locTr1,obj1);
            //Record the created threads.
            Thread *tr1 = this->locTr1->getTr(this);
            this->trs.push_back(tr0);
            if (tr1 != tr0) {
                this->trs.push_back(tr1);
            }
            //Add U/F constraint: U must happen after F.
            this->poc->addConstraint(this->locTr0.get(), this->locTr1.get());
            return 0;
        }

        //Add escape/fetch path nodes and related constraints to the
        //thread schedule to trigger the UAF.
        int addEFPaths(EqvObjPair *ep0, EqvObjPair *ep1);

        //Add the path nodes that enable the required pto at the F/U sites
        //(e.g., make the "p" in free(p) point to the desired "fobj" but not others).
        int addPtoPaths(AliasObject *fobj, AliasObject *uobj);

        //Add the provided InstLoc to the thread pool, but with the threads
        //in the "blocklist" excluded. If no existing thread can receive the
        //"loc", create a new one if "create" is true.
        //Return: the "InstLocTr" instance if succeded, nullptr if failed.
        //If "ec" is not null, fill in the insertion error code as obtained from
        //the thread-level "insertLoc()" function.
        //If "dom" is true, the insertion is only performed if "loc" dominates or
        //post-dominates an existing InstLoc in the thread (e.g., inevitable).
        std::shared_ptr<InstLocTr> addLoc(InstLoc *loc, int ty, std::set<Thread*> *blockList = nullptr,
                            bool dom = false, bool create = true, int *ec = nullptr) {
            if (!loc) {
                return nullptr;
            }
            for (Thread *tr : this->trs) {
                if (!tr) {
                    continue;
                }
                if (blockList && blockList->find(tr) != blockList->end()) {
                    //Black listed, skip.
                    continue;
                }
                //Try inserting.
                std::shared_ptr<InstLocTr> locTr = tr->insertLoc(loc, ty, true, dom, ec);
                if (locTr) {
                    return locTr;
                }
            }
            //Ok, all failed, see whether to create a new thread.
            if (create) {
                std::shared_ptr<InstLocTr> locTr = this->initThread(loc, ty);
                if (locTr)
                    this->trs.push_back(locTr->getTr(this));
                return locTr;
            }
            return nullptr;
        }

        //For each loc in the current threads, insert their important supplementary InstLocs
        //(e.g., lock/unlock, condition check/set, etc.). 
        int addSuppTrLocs();

        //Add the thread sync related InstLocs (e.g., fork, join) and add the related
        //happens-before partial order constraints.
        int addSyncTrLocs();

        //Add the natural intra-thread partial-order constraints to this schedule.
        //(including all the alternative ones).
        void addSeqConstraint() {
            for (Thread *tr : this->trs) {
                if (!tr) {
                    continue;
                }
                for (unsigned i = 0; i + 1 < tr->seq.size(); ++i) {
                    this->poc->addConstraint(tr->seq[i].get(), tr->seq[i + 1].get());
                }
            }
            return;
        }

        //Add the natural intra-thread partial-order constraints to all schedules
        //(including the alternative ones).
        void addSeqConstraint2All() {
            this->addSeqConstraint();
            for (ThreadSched *altSched : this->altScheds) {
                altSched->addSeqConstraint2All();
            }
            return;
        }

        //Decide whether this sched is feasible (regarding the partial-order constraints),
        //if so, provide a possible solution that is basically an execution sequence of
        //all InstLocTr.
        bool validate(std::vector<void*> *solution = nullptr) {
            return this->poc->solve(solution);
        }

        //Decide whether this sched or any alternative one is feasible, stop and return
        //true as soon as one feasible sched is found.
        bool validateAll(std::vector<void*> *solution = nullptr) {
            if (this->validate(solution)) {
                return true;
            }
            for (ThreadSched *altSched : this->altScheds) {
                if (altSched->validateAll(solution)) {
                    return true;
                }
            }
            return false;
        }

    private:
        //Add the lock/unlock around the "loc" into its host thread.
        int addLockTrLocs(std::shared_ptr<InstLocTr> loc,
                            std::set<std::shared_ptr<InstLocTr>> &newLocs);

        //Add the path condition set/check InstLocs around the specified "loc".
        int addCondTrLocs(std::shared_ptr<InstLocTr> loc,
                            std::set<std::shared_ptr<InstLocTr>> &newLocs);
        
        //Create and init a new thread with the provided InstLoc.
        std::shared_ptr<InstLocTr> initThread(InstLoc *loc, int ty = InstLocTr::TY_DEF) {
            if (!loc) {
                return nullptr;
            }
            Thread *tr = new Thread(this->trs.size(), this);
            //Add locTr to the thread.
            std::shared_ptr<InstLocTr> locTr = tr->insertLoc(loc, ty);
            if (!locTr) {
                //This seems impossible...
                dbgs() << "!!! Fail to insert InstLoc to an inited Thread!\n";
                delete(tr);
            }
            return locTr;
        }

        //Add one EF path to the thread sched and put the related partial-order constraints.
        int addOneEFPath(EqvObjPair *ep, std::shared_ptr<InstLocTr> endLocTr);

        //Add one pto path "seq" for "locTr".
        int addOnePtoPath(std::shared_ptr<InstLocTr> locTr,
                          std::vector<InstLoc*> &seq);

        //Decide whether a cond set loc must kill the related cond check loc in the sched.
        bool _mustKill(std::shared_ptr<InstLocTr> clocTr, std::shared_ptr<InstLocTr> klocTr);

        //Decide whether a cond set loc may not kill the related cond check loc in the sched.
        bool _noKill(std::shared_ptr<InstLocTr> clocTr, std::shared_ptr<InstLocTr> klocTr);

        //Add a pair of thread-sync InstLocs (e.g., pthread_create() and pthread_join()) to
        //all applicable threads in the sched, while "ptTr" is the created pthread that is
        //controlled by these sync events.
        int addSyncPair(InstLoc *stLoc, InstLoc *edLoc, Thread *ptTr);
    };

    //This class abstracts the information related to callbacks
    //(e.g., interrupt handlers) or threads (e.g., pthread_create()) in the program,
    //including both the callback entries themselves and their registration sites.
    class CallBackInfo {
    public:
        //arg no -> its pto records.
        std::map<int, std::set<PointerPointsTo*>> arg_ptos;
        //this is for happens-before analysis, e.g., the thread created by
        //pthread_create() can only execute in parallel with the code between
        //pthread_create() and pthread_join(), we record such range info here. 
        std::map<InstLoc*,std::set<InstLoc*>> ranges;
        //Specific to pthread model, this maps the pthread_create() call sites
        //to the pto used to store the thread id.
        std::map<InstLoc*,std::set<PointerPointsTo*>> pc2tidMap;

        CallBackInfo() {}

        CallBackInfo(CallBackInfo &other) {
            this->arg_ptos = other.arg_ptos;
            this->ranges = other.ranges;
            this->pc2tidMap = other.pc2tidMap;
        }

        void print(raw_ostream &O) {
            O << "Arg Pto:\n";
            for (auto &e : arg_ptos) {
                O << e.first << " : ";
                for (PointerPointsTo *p : e.second) {
                    if (p) {
                        O << (const void *)(p->targetObject) << "|"
                          << p->dstfieldId << ", ";
                    }
                }
                O << "\n";
            }
            O << "Ranges:\n";
            for (auto &e : this->ranges) {
                if (e.first) {
                    e.first->print_light(O, false);
                }
                O << " --> ";
                for (InstLoc *ed : e.second) {
                    if (ed) {
                        ed->print_light(O, false);
                        O << " | ";
                    }
                }
                O << "\n";
            }
            //For debug purpose, print "pc2tidMap" if any.
            if (!this->pc2tidMap.empty()) {
                O << "pc2tidMap:\n";
                for (auto &e : this->pc2tidMap) {
                    if (e.first) {
                        e.first->print_light(O, false);
                    }
                    O << " : ";
                    for (PointerPointsTo *p : e.second) {
                        if (p) {
                            O << (const void *)(p->targetObject) << "|"
                              << p->dstfieldId << ", ";
                        }
                    }
                    O << "\n";
                }
            }
        }

        void merge(CallBackInfo &other) {
            //Merge arg_ptos
            for (auto &e : other.arg_ptos) {
                if (e.second.empty()) {
                    continue;
                }
                this->addArgPto(e.first, &e.second);
            }
            //Merge ranges
            for (auto &e : other.ranges) {
                for (InstLoc *loc : e.second) {
                    this->ranges[e.first].insert(loc);
                }
            }
            //Merge pc2tidMap.
            for (auto &e : other.pc2tidMap) {
                for (PointerPointsTo *pto : e.second) {
                    this->_insPto2Set(this->pc2tidMap[e.first], pto);
                }
            }
            return;
        }

        int addRange(InstLoc *st, InstLoc *ed) {
            //NOTE: we allow a null "ed" loc, which means it's to be decided later.
            if (!st) {
                return -1;
            }
            auto &exist = this->ranges[st];
            if (ed) {
                exist.insert(ed);
            }
            return 0;
        }

        int addArgPto(int no, std::set<PointerPointsTo*> *ptos, bool copy = false) {
            if (!ptos || ptos->empty()) {
                return 0;
            }
            auto &exist = this->arg_ptos[no];
            for (PointerPointsTo *p : *ptos) {
                if (!p) continue;
                this->_insPto2Set(exist, 
                (copy ? new PointerPointsTo(nullptr,p->targetObject,p->dstfieldId) : p));
            }
            return 0;
        }

        int addPc2Tid(InstLoc *loc, std::set<PointerPointsTo*> *ptos) {
            if (!loc || !ptos || ptos->empty()) {
                return 0;
            }
#ifdef DEBUG_CALLBACK_ANALYSIS
            //dbgs() << "addPc2Tid(): loc: " << (const void*)loc << ", #ptos: " << ptos->size() << ", ";
            //loc->print_light(dbgs(),true);
#endif
            auto &exist = this->pc2tidMap[loc];
            for (PointerPointsTo *np : *ptos) {
                this->_insPto2Set(exist, np);
            }
            return 0;
        }

        //The "tptos" records the mem locs used to store thread id used at a
        //pthread_join() site, this function tries to decide whether this join
        //site is paired with the pthread_create() site related to this callback,
        //by matching the mem locs of the thread id. If so, the "ranges" will
        //be accordingly updated to include the create (start point) and the
        //join (end point). 
        int matchPcSites(InstLoc *jloc, std::set<PointerPointsTo*> &tptos) {
            if (!jloc || tptos.empty() || this->pc2tidMap.empty()) {
                return 0;
            }
            for (auto &e : this->pc2tidMap) {
                InstLoc *pcloc = e.first;
                if (!pcloc || e.second.empty() || !jloc->reachable(pcloc)) {
                    continue;
                }
                for (PointerPointsTo *np : e.second) {
                    if (std::find_if(tptos.begin(), tptos.end(),
                                     [np](PointerPointsTo *p) {
                                         //Make it more strict - two variable indices of
                                         //an array may not be aliased.
                                         return np->pointsToSameObject(p) &&
                                                np->dstfieldId >= 0;
                                     }) != tptos.end())
                    {
                        // Matched PC site, add the "range" entry.
#ifdef DEBUG_CALLBACK_ANALYSIS
                        dbgs() << "matchPcSites(): add pthread range, CREATE: ";
                        pcloc->print_light(dbgs(), false);
                        dbgs() << ", JOIN: ";
                        jloc->print_light(dbgs(), true);
#endif
                        this->addRange(pcloc, jloc);
                        break;
                    }
                }
            }
            return 0;
        }

        //Return true if the loadTags in arg_ptos of this cbi matches the "ids".
        bool matchArgPtoTag(std::map<void*,std::set<long>> *ids) {
            if (!ids || ids->empty()) {
                return true;
            }
            for (auto &e : this->arg_ptos) {
                for (PointerPointsTo *pto : e.second) {
                    if (!pto || pto->loadTag.empty()) {
                        continue;
                    }
                    TypeField *tag = pto->loadTag[0];
                    if (ids->find((void*)(tag->v)) != ids->end() &&
                        (*ids)[(void*)(tag->v)].find(tag->fid) != (*ids)[(void*)(tag->v)].end()) {
                            return true;
                    }
                }
            }
            return false;
        }

private:
        void _insPto2Set(std::set<PointerPointsTo *> &exist, PointerPointsTo *np) {
            if (!np) {
                return;
            }
            if (std::find_if(exist.begin(), exist.end(),
                             [np](PointerPointsTo *p) {
                                 return np->pointsToSameObject(p);
                             }) == exist.end()) {
                exist.insert(np);
            }
        }
    };

    //This class manages all the CallBackInfo instances related to a same callback
    //entry function (e.g., one entry can be registered at different sites, resulting
    //in different CallBackInfo instances.).
    class CallBackDir {
    public:
        //The key of "dir" (void*) is used to differentiate two callbacks, e.g.,
        //- can be a Function* of the callback, this means we ignore the differences
        //of their registration sites (a sam callback entry can be registered at
        //different sites)
        //- can be the Instruction* of the reg site, this means a same callback entry
        //registered by different Instructions are also differentiated.
        //- can be InstLoc* of the reg site, this adds the context-sensitivity of
        //the reg site to the above.
        std::map<void*,CallBackInfo*> dir;

        CallBackDir() {}

        int addCB(void *key, CallBackInfo *cbi) {
            if (!cbi) {
                return 0;
            }
            if (this->dir.find(key) == this->dir.end() || !this->dir[key]) {
                this->dir[key] = new CallBackInfo(*cbi);
            } else {
                this->dir[key]->merge(*cbi);
            }
            return 0;
        }

        CallBackInfo *getCB(void *key) {
            if (this->dir.find(key) != this->dir.end()) {
                return this->dir[key];
            }
            return nullptr;
        }

        //A wrapper of a same named function in CBI.
        void matchPcSites(InstLoc *jloc, std::set<PointerPointsTo*> &tptos) {
            for (auto &e : this->dir) {
                if (e.second) {
                    e.second->matchPcSites(jloc, tptos);
                }
            }
            return;
        }

        void print(raw_ostream &O) {
            for (auto &e : this->dir) {
                O << "key: " << (const void*)(e.first) << "\n";
                if (e.second) {
                    e.second->print(O);
                }
            }
        }

        //Obtain all the ranges of CBIs that match the "ids" (i.e., loadTag of the
        //pto records of arg).
        //If "ids" is nullptr, then just combine and return all ranges w/o matching.
        int getCallbackRange(std::map<InstLoc*,std::set<InstLoc*>> &res,
                             std::map<void*,std::set<long>> *ids = nullptr)
        {
            for (auto &e : this->dir) {
                if (!e.second || !e.second->matchArgPtoTag(ids)) {
                    continue;
                }
                for (auto &e0 : e.second->ranges) {
                    if (!e0.first || e0.second.empty()) {
                        continue;
                    }
                    for (InstLoc *edLoc : e0.second) {
                        if (edLoc) {
                            res[e0.first].insert(edLoc);
                        }
                    }
                }
            }
            return 0;
        }
    };

    static std::set<std::vector<TypeField*>*> htys;
    static std::set<size_t> chainHash;
    static std::set<std::string> hstrs;
    static std::set<std::set<AliasObject*>*> eqObjs;

    extern bool _isUseFromLocalPtr(InstLoc *uloc, AliasObject *obj);

    extern bool _isFreeFromLocalPtr(InstLoc *floc, AliasObject *obj);

    extern bool _isPtoFromLocalPtr(ObjectPointsTo *pto, CallContext *ctx);

    extern bool _hasGlobalEscape(std::vector<AliasObject*> &his, InstLoc *refloc = nullptr,
                                    Thread *reflocs = nullptr, int pos = 0);

    // Decide whether the F/U sites are protected by the refcnt mechanism.
    extern bool _isWithRefcnt(InstLoc *floc, InstLoc *uloc);

    extern bool _hasUnrelObjBoundIndirectCalls(InstLoc *loc0, InstLoc *loc1);

    extern bool _canRefSameHeapObj(InstLoc *aloc, InstLoc *loc0, InstLoc *loc1, int dir = 0);

    /***
     *  Object which represents GlobalState.
     *  Everything we need in one place.
     *  Refer Fig1 in the paper.
     *  It contains pointsTo, globalVariables and TaintInformation.
     */
    class GlobalState {
    public:

        // map containing analysis context to corresponding vulnerability warnings.
        std::map<CallContext*, std::set<VulnerabilityWarning*>*> allVulnWarnings;

        // map containing vulnerability warnings w.r.t instruction.
        std::map<Instruction*, std::set<VulnerabilityWarning*>*> warningsByInstr;

        //is the current function being analyzed read/write?
        bool is_read_write_function = false;

        // Map, which contains at each instruction.
        // set of objects to which the pointer points to.
        // Information needed for AliasAnalysis
        std::map<CallContext*, std::map<Value*, std::set<PointerPointsTo*>*>*> pointToInformation;

        // Information needed for TaintAnalysis
        std::map<CallContext*, std::map<Value *, std::set<TaintFlag*>*>*> taintInformation;

        static std::map<Value *, std::set<PointerPointsTo*>*> globalVariables;

        static std::map<Function*, std::set<BasicBlock*>*> loopExitBlocks;

        // Data layout for the current module
        DataLayout *targetDataLayout;

        // Store the value constraints imposed by different paths.
        // Note that the key "CallContext*" can be nullptr, in that case,
        // the value constraint applies in all the calling contexts. 
        std::map<CallContext*, std::map<Value*, Constraint*>> constraintInformation;

        // For each branch inst analyzed in our path analysis pass, it either:
        // (1) follows a simple cmp pattern and we generate a "Constraint" for
        // its conditional variable (mapped to the Constraint*), or
        // (2) we tried but no "Constraint" was generated (mapped to nullptr).
        std::map<BranchInst*, Constraint*> brConstraints;

        // Record the lock/unlock entries.
        std::vector<LockInfo*> locks, unlocks;

        // Record the objects that ever get freed somewhere.
        std::set<AliasObject*> freedObjs;

        // These are the infeasible (due to conflicting path constraints) basic blocks under each calling context.
        // If the "CallContext*" is nullptr, the BBs are dead in all contexts.
        std::map<CallContext*, std::set<BasicBlock*>> deadBBs;

        // a map of basic block to number of times it is analyzed.
        std::map<const BasicBlock*, unsigned long> numTimeAnalyzed;

        // Map the updating instructions to their update patterns.
        std::map<Instruction*, TraitSet*> updatePatterns;

        // Map the conditional instructions (e.g., br, switch)
        // to their check patterns and checked variable.
        std::map<Instruction*, std::pair<TraitCheck*, Value*>> checkPatterns;

        // Map the br InstLocs to the corresponding comparison patterns and obj|field
        // involved.
        std::map<InstLoc*, std::map<AliasObject*, std::map<long, std::set<TraitCheck*>>>> traitChecks;

        std::map<InstLoc*, std::map<CallInst*, std::set<TraitCheck*>>> traitCheckRets;

        std::map<InstLoc*, std::map<PHINode*, std::set<TraitCheck*>>> traitCheckPHIs;

        //Record the identified callback functions that should also be analyzed as
        //driver entries.
        //e.g., the bottom-half interrupt handlers, like workqueue/tasklet functions.
        //callback type -> function -> CallBackInfo
        //callback type: 0:workqueue, 1:tasklet, 2:pthread
        std::map<int,std::map<Function*,CallBackDir*>> callbacks;

        //Indicates the analysis phase we're currently in, now:
        //1 = preliminary phase, 2 = main analysis phase, 3 = bug detection phase.
        int analysis_phase = 0;

        //Top-down style analysis can spend much time repeatedly analyzing the same function
        //in different contexts, if this becomes a big problem, this option can be set to
        //aggressively skip some frequent and time-consuming functions, but the analysis
        //result can be no longer sound.
        //NOTE: TIMING must be defined to use this option.
        unsigned funcTimeLimit = 0;

#ifdef TIMING
        //func -> its top entry -> <#occurence, #total time spent>
        std::map<Function*,std::map<Function*,std::pair<unsigned,double>>> funcTime;
        std::chrono::time_point<std::chrono::system_clock> t_start;
#endif

        GlobalState(DataLayout *currDataLayout) {
            this->targetDataLayout = currDataLayout;
        }

        ~GlobalState() {
            cleanup();

        }

        void cleanup() {
            // clean up
            std::set<AliasObject*> deletedObjects;
            // all global variables.
            for(auto glob_iter = globalVariables.begin(); glob_iter != globalVariables.end(); glob_iter++) {
                auto targetPointsTo = glob_iter->second;
                for(auto currPointsTo: *targetPointsTo) {
                    auto targetAliasObj = currPointsTo->targetObject;
                    if(deletedObjects.find(targetAliasObj) == deletedObjects.end()) {
                        deletedObjects.insert(targetAliasObj);
                        delete(targetAliasObj);
                    }
                    delete(currPointsTo);
                }
                delete(targetPointsTo);
            }
            globalVariables.clear();

            // all pointsToInformation
            for(auto ptInfo = pointToInformation.begin(); ptInfo != pointToInformation.end(); ptInfo++) {
                for(auto pointsTo_iter = ptInfo->second->begin(); pointsTo_iter != ptInfo->second->begin();
                    pointsTo_iter++) {
                    auto targetPointsTo = pointsTo_iter->second;
                    for(auto currPointsTo: *targetPointsTo) {
                        auto targetAliasObj = currPointsTo->targetObject;
                        if(deletedObjects.find(targetAliasObj) == deletedObjects.end()) {
                            deletedObjects.insert(targetAliasObj);
                            delete(targetAliasObj);
                        }
                        delete(currPointsTo);
                    }
                    delete(targetPointsTo);
                }
            }
            pointToInformation.clear();
        }

        std::set<PointerPointsTo *> *getPointsToObjects(CallContext *ctx, Value *v) {
            std::map<Value *, std::set<PointerPointsTo *> *> *pmap = this->getPointsToInfo(ctx);
            // Here srcPointer should be present in points to map.
            if (pmap->find(v) != pmap->end()) {
                return (*pmap)[v];
            }
            // Don't forget the global pto records.
            if (GlobalState::globalVariables.find(v) != GlobalState::globalVariables.end()) {
                return GlobalState::globalVariables[v];
            }
            return nullptr;
        }

        void printCallbacks(raw_ostream &O) {
            for (auto &e0 : this->callbacks) {
                int f_cls = e0.first;
                for (auto &e1 : e0.second) {
                    Function *func = e1.first;
                    if (!func || func->isDeclaration()) {
                        continue;
                    }
                    O << "Ty: " << f_cls << ", Func: " << func->getName().str() << "\n";
                    if (e1.second) {
                        O << "CallBackInfo:\n";
                        e1.second->print(O);
                    }
                }
            }
        }

        //Return the parallel range of callback thread "tr" if any.
        //"objs" contains the objects involved in the data flow of "tr".
        int getCallbackRange(Thread *tr, std::map<InstLoc*,std::set<InstLoc*>> &res)
        {
            if (!tr || tr->seq.empty()) {
                return 0;
            }
            //First check whether this thread is within a callback function.
            Function *f = tr->getEntryFunc();
            if (!f ||
                this->callbacks.find(2) == this->callbacks.end() ||
                this->callbacks[2].find(f) == this->callbacks[2].end() ||
                !this->callbacks[2][f]) {
                return 0;
            }
            CallBackDir *cbd = this->callbacks[2][f];
            //We need to decide which CallBackInfo this callback thread relates
            //to, this is done by matching the loadTag of the pto records in
            //this thread.
            std::map<void*,std::set<long>> ids;
            for (auto &locTr : tr->seq) {
                if (!locTr || locTr->ptos.empty()) {
                    continue;
                }
                //Extract the loadTags of the relevant ptos.
                for (auto &e : locTr->ptos) {
                    for (PointerPointsTo *pto : e.second) {
                        if (!pto || pto->loadTag.empty()) {
                            continue;
                        }
                        TypeField *tag = pto->loadTag[0];
                        if (tag) {
                            ids[(void *)(tag->v)].insert(tag->fid);
                        }
                    }
                }
            }
            cbd->getCallbackRange(res,&ids);
            //dbgs() << "getCallbackRange(): #ranges w/ filtering: " << res.size() << "\n";
            if (res.empty()) {
                //To be conservative, just obtain all possible ranges w/o matching.
                cbd->getCallbackRange(res,nullptr);
                //dbgs() << "getCallbackRange(): #ranges w/o filtering: " << res.size() << "\n";
            }
            return 0;
        }

        int getCondKillerLocsObj(InstLoc *cloc, unsigned dst, std::set<InstLoc*> &klocs) {
            if (!cloc || this->traitChecks.find(cloc) == this->traitChecks.end()) {
                return 0;
            }
            klocs.clear();
            //First collect all the obj|fid and their related TraitChecks need to be matched.
            std::map<AliasObject*, std::map<long, std::set<TraitCheck*>>> to_check;
            for (auto &e0 : this->traitChecks[cloc]) {
                AliasObject *obj = e0.first;
                assert(obj);
                //Get all the equivalent objs for later use.
                std::map<AliasObject*,EqvObjPair*> eobjs;
                obj->getEqvObjs(eobjs);
                for (auto &e1 : e0.second) {
                    long fid = e1.first;
                    for (TraitCheck *tc : e1.second) {
                        assert(tc);
                        //Current situation: at cloc, obj|fid has been checked following the
                        //pattern as defined in the TraitCheck "tc".
                        //Now we need to find out whether there are any TraitSet InstLocs associated
                        //with obj|fid (and all its aliases) that can kill this condition|dst.
                        for (auto &e2 : eobjs) {
                            AliasObject *eobj = e2.first;
                            if (!eobj) {
                                continue;
                            }
                            to_check[eobj][fid].insert(tc);
                        }
                    }
                }
            }
            //Now match the killers.
            for (auto &e0 : to_check) {
                AliasObject *obj = e0.first;
                for (auto &e1 : e0.second) {
                    long fid = e1.first;
#ifdef DEBUG_ADD_SUPP_LOC
                    //dbgs() << "getCondKillerLocsObj(): checking obj|fid: "
                    //<< (const void*)obj << "|" << fid << "\n";
#endif
                    for (TraitCheck *tc : e1.second) {
#ifdef DEBUG_ADD_SUPP_LOC
                        //dbgs() << "check tc: ";
                        //tc->print(dbgs(), false);
                        //dbgs() << ", dst: " << dst << "\n";
#endif
                        //Find the InstLocs that can kill the desired branch.
                        std::set<InstLoc*> res;
                        obj->getKillerTraitSetLocs(tc, dst, fid, res);
                        klocs.insert(res.begin(), res.end());
                    }
                }
            }
#ifdef DEBUG_ADD_SUPP_LOC
            dbgs() << "getCondKillerLocsObj(): #klocs: " << klocs.size() << "\n";
#endif
            return 1;
        }
        
        //Try to find the InstLocs under the calling ctx "cctx" that once reached,
        //will lead to a return value conflicting with "echk" (z3 expr created under
        //the global z3 context).
        //Note that we do not try to find all such InstLocs within the function,
        //but only those directly connected to the return BB, or the return BB itself
        //if applicable.
        int _getKillerRets(CallContext *cctx, z3::expr &echk, 
                            std::set<InstLoc*> &klocs) {
            if (!cctx || !cctx->callSites || cctx->callSites->empty()) {
                return 0;
            }
#ifdef DEBUG_ADD_SUPP_LOC
            dbgs() << "_getKillerRets(): find killer locs in the ctx: ";
            cctx->print(dbgs(), true);
#endif
            Instruction *einst = cctx->callSites->back();
            Function *func = einst->getFunction();
            if (!func) {
                return 0;
            }
            //First get all the return BBs.
            std::set<BasicBlock*> rbbs;
            BBTraversalHelper::getRetBBs(func, rbbs);
            // Store all the killer paths related to this ret value, a killer path
            // is a BB sequence to the ret BB that if followed, will generate the
            // ret value making the "echk" infeasible.
            std::set<std::vector<BasicBlock*>> kseqs;
            std::map<Value*, std::set<std::vector<BasicBlock*>>> openSeqs;
            for (BasicBlock *rbb : rbbs) {
                //Get the return inst.
                Instruction *ri = rbb->getTerminator();
                if (!dyn_cast<ReturnInst>(ri)) {
                    continue;
                }
                //Get the return value.
                Value *rv = dyn_cast<ReturnInst>(ri)->getReturnValue();
                if (!rv) {
                    continue;
                }
                //Start from the ret value in the ret BB.
                std::vector<BasicBlock*> seq{rbb};
                openSeqs[rv].insert(seq);
            }
            //Detect whether current function is simply a wrapper of another
            //one (e.g., returns another func's return), if so, the killer
            //identification should be delegated.
            //TODO: we need to extend this (e.g., ret is a phi and one incoming
            //value is a ret from another func).
            if (openSeqs.size() == 1) {
                Value *rv = openSeqs.begin()->first;
                if (!this->getAvailableConstraints(cctx, rv)) {
                    rv = InstructionUtils::stripAllCasts(rv,false);
                    if (rv && dyn_cast<CallInst>(rv)) {
                        //Now we don't have any constraints for the ret
                        //in current ctx, and we decide that the ret is
                        //actually from another wrapped function, so we
                        //can and need to delegate the analysis.
                        std::set<CallContext*> callCtxs;
                        CallContext::getCalleeCtx(cctx, *dyn_cast<CallInst>(rv),
                                                  callCtxs);
#ifdef DEBUG_ADD_SUPP_LOC
                        dbgs() << "_getKillerRets(): function wrapper detected, go"
                        << " up into the callee, #cctx: " << callCtxs.size() << "\n";
#endif
                        for (CallContext *c2ctx : callCtxs) {
                            std::set<InstLoc*> tklocs;
                            _getKillerRets(c2ctx, echk, tklocs);
                            klocs.insert(tklocs.begin(), tklocs.end());
                        }
                        return 0;
                    }
                }
            }
#ifdef DEBUG_ADD_SUPP_LOC
            dbgs() << "_getKillerRets(): #ret BBs: " << rbbs.size() << ", #ret vals: "
            << openSeqs.size() << "\n";
#endif
            this->_getKseqs(cctx, echk, openSeqs, kseqs);
#ifdef DEBUG_ADD_SUPP_LOC
            dbgs() << "_getKillerRets(): #killer seqs: " << kseqs.size() << "\n";
#endif
            //Identify the killer InstLocs based on the killer sequences.
            if (!kseqs.empty()) {
                this->_getKlocsFromSeqs(cctx, kseqs, klocs);
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "_getKillerRets(): #klocs: " << klocs.size() << "\n";
#endif
            }
            return 0;
        }

        int _getKseqs(CallContext *cctx, z3::expr &echk,
                      std::map<Value*, std::set<std::vector<BasicBlock*>>> &openSeqs,
                      std::set<std::vector<BasicBlock*>> &kseqs) {
            //We need to first ensure that "echk" is satisfiable by itself.
            z3::solver z3s(z3c);
            z3s.add(echk);
            if (z3s.check() == z3::unsat) {
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "_getKseqs(): echk is unsat!\n";
#endif
                return 0;
            }
            std::map<Value*, std::set<std::vector<BasicBlock*>>> newSeqs;
            //Calculate the killer paths.
            while (!openSeqs.empty()) {
                for (auto &e0 : openSeqs) {
                    Value *v = e0.first;
                    for (const std::vector<BasicBlock*> &seq : e0.second) {
                        BasicBlock *curBB = seq[0];
                        //Is current BB reachable under "cctx"?
#ifdef DEBUG_ADD_SUPP_LOC
                        //dbgs() << "_getKseqs(): check the value: "
                        //<< InstructionUtils::getValueStr(v) << " @ BB: "
                        //<< InstructionUtils::getBBStrID(curBB) << "\n";
#endif
                        if (this->isDeadBB(cctx, curBB)) {
                            //Impossible to reach the current BB in the context "cctx",
                            //so we will not have a killer sequence involving it as well.
#ifdef DEBUG_ADD_SUPP_LOC
                            //dbgs() << "_getKseqs(): dead BB!\n";
#endif
                            continue;
                        }
                        //Does the constraint of "v" at the current BB kill the "echk"?
                        //Simple cases first: if "v" is a constant.
                        if (dyn_cast<Constant>(v)) {
                            int64_t sc;
                            uint64_t uc;
                            if (!InstructionUtils::getConstantValue(dyn_cast<Constant>(v),
                                                                    &sc, &uc)) {
                                continue;
                            }
#ifdef DEBUG_ADD_SUPP_LOC
                            //dbgs() << "_getKseqs(): the value is a constant: " << sc << "\n";
#endif
                            z3s.reset();
                            z3s.add(echk);
                            z3s.add(z3c.bv_const("v", 64) == z3c.bv_val(sc, 64));
                            if (z3s.check() == z3::unsat) {
                                //This is a killer path!
#ifdef DEBUG_ADD_SUPP_LOC
                                //dbgs() << "_getKseqs(): the value kills the echk!\n";
#endif
                                kseqs.insert(seq);
                            }
                            //If this is a killer path, we should continue to process the
                            //next one, if not, since it's not a phi node, we have no further
                            //seqs to track, so either way, we should skip now.
                            continue;
                        }
                        Constraint *con = this->getAvailableConstraints(cctx, v);
                        if (!con) {
                            //Even if "v" is a phi-node produced merged value, our path
                            //analysis can handle it and generate the constraints, now
                            //it doesn't have any constraints, that's because our current
                            //path analysis doesn't support it (e.g., "v" results from an
                            //arithemtic calculation and is not compared with constants),
                            //we are then not sure any more about whether there is a
                            //killer path.
#ifdef DEBUG_ADD_SUPP_LOC
                            //dbgs() << "_getKseqs(): non-constant value, but we don't have any"
                            //<< " constraints on file - 1.\n";
#endif
                            continue;
                        }
                        if (!con->hasConstraint(curBB)) {
                            //Similar reasoning as above.
#ifdef DEBUG_ADD_SUPP_LOC
                            //dbgs() << "_getKseqs(): non-constant value, but we don't have any"
                            //<< " constraints on file - 2.\n";
#endif
                            continue;
                        }
                        z3::expr eex = *con->cons[curBB];
                        //Ensure that rcon by itself is satisfiable.
#ifdef DEBUG_ADD_SUPP_LOC
                        //dbgs() << "_getKseqs(): the value constraint (in z3 expr): "
                        //<< rcon.to_string() << "\n";
#endif
                        z3s.reset();
                        z3s.add(eex);
                        if (z3s.check() == z3::unsat) {
                            //This seems impossible, because if this happens, the BB should
                            //have been treated as dead.
#ifdef DEBUG_ADD_SUPP_LOC
                            //dbgs() << "_getKseqs(): the constraint on the value itself is"
                            //<< " unsat!\n";
#endif
                            continue;
                        }
                        //Ok, now both "echk" and "rcon" are satisfiable by themselves, so if
                        //the AND of them is unsatisfiable, we can see "rcon" kills "echk".
                        z3s.add(get_z3v() == get_z3v_expr_bv(v));
                        z3s.add(echk);
                        if (z3s.check() == z3::unsat) {
                            //Record the killer path.
#ifdef DEBUG_ADD_SUPP_LOC
                            //dbgs() << "_getKseqs(): the value kills the echk!\n";
#endif
                            kseqs.insert(seq);
                            continue;
                        }
                        //"v" @ "curBB" cannot kill "echk", we need to further trace it back
                        //if "v" is a phi-node merge.
                        PHINode *pi = dyn_cast<PHINode>(v);
                        if (!pi) {
                            //Try stripping the cast?
                            Value *vs = InstructionUtils::stripAllCasts(v,false);
                            if (vs) {
                                pi = dyn_cast<PHINode>(vs);
                                if (pi && pi->getParent() != curBB) {
                                    //current "v" is converted from a phi at a different
                                    //BB... If we just go as is, our "seq" will be
                                    //incomplete and may cause troubles later.
                                    //TODO: ideally we need to recover the paths from
                                    //phi's BB to curBB and update the "seq"
                                    pi = nullptr;
                                }
                            }
                        }
                        if (pi) {
#ifdef DEBUG_ADD_SUPP_LOC
                            //dbgs() << "_getKseqs(): the value doesn't kill at current BB, "
                            //<< "but it is a phi-node, so keep tracking.\n";
#endif
                            for (unsigned i = 0; i < pi->getNumIncomingValues(); ++i) {
                                Value *v = pi->getIncomingValue(i);
                                BasicBlock *bb = pi->getIncomingBlock(i);
                                if (!v || !bb) {
                                    continue;
                                }
#ifdef DEBUG_ADD_SUPP_LOC
                                //dbgs() << "_getKseqs(): extend the seq to: "
                                //<< InstructionUtils::getValueStr(v) << " @ BB: "
                                //<< InstructionUtils::getBBStrID(bb) << "\n";
#endif
                                if (std::find(seq.begin(), seq.end(), bb) != seq.end()) {
                                    //A loop in the path, ignore.
#ifdef DEBUG_ADD_SUPP_LOC
                                    //dbgs() << "_getKseqs(): loop in the seq, skip...\n";
#endif
                                    continue;
                                }
                                std::vector<BasicBlock*> newSeq(seq);
                                newSeq.insert(newSeq.begin(), bb);
                                newSeqs[v].insert(newSeq);
                            }
                        }
                    }
                } //for-loop explore the current batch of open seqs.
                openSeqs = newSeqs;
                newSeqs.clear();
            }
            return 1;
        }

        Instruction *_pickInstFromBB(BasicBlock *bb) {
            if (!bb) {
                return nullptr;
            }
            Instruction *i = bb->getTerminator();
            if (!i) {
                dbgs() << "!!! _pickInstFromBB(): BB w/o a terminator: "
                << InstructionUtils::getBBStrID(bb) << "\n";
                i = bb->getFirstNonPHIOrDbg();
                if (!i) {
                    // very unlikely.
                    dbgs() << "!!! _pickInstFromBB(): and even no non-phi or dbg...\n";
                }
            }
            return i;
        }

        //pre-condition: "cp" is already within one or more seqs in "kseqs".
        //return true if there is at least one path continuing "cp" to the return that
        //doesn't fall in any seq in "kseqs".
        //If there is anything unusual (e.g., null BB or terminator), assume that kseqs
        //can be escaped for conservativity.
        //NOTE: all path and kseqs have their element 0 as the starting BB.
        bool _escapeKseq(std::vector<BasicBlock*> &cp, 
                         std::set<const std::vector<BasicBlock*>*> &kseqs) {
            if (cp.empty()) {
                return true;
            }
            BasicBlock *currBB = cp.back();
            if (!currBB || !currBB->getTerminator()) {
                return true;
            }
            if (currBB->getTerminator()->getNumSuccessors() == 0) {
                // The current BB is the return BB, since "cp" is still in kseq,
                // it doesn't escape eventually.
                return false;
            }
            //Explore the successors.
            std::set<BasicBlock*> to_do;
            for (llvm::succ_iterator sit = llvm::succ_begin(currBB);
                 sit != llvm::succ_end(currBB); ++sit) {
                BasicBlock *succBB = *sit;
                if (!succBB) {
                    continue;
                }
                if (std::find(cp.begin(), cp.end(), succBB) != cp.end()) {
                    // Explored node, ignore.
                    continue;
                }
                //See whether cp + succBB escapes all kseqs.
                cp.push_back(succBB);
                bool esc = true;
                bool cont_explore = true;
                for (auto &e : kseqs) {
                    if (std::equal(e->begin(), e->end(), cp.begin())) {
                        //This means current path is prefixed w/ one kseq,
                        //so it certainly cannot escape, as well as all
                        //paths prefixed with current path, in other words
                        //no need to continue exploring from "succBB".
                        esc = false;
                        cont_explore = false;
                        break;
                    }
                    if (std::equal(cp.begin(), cp.end(), e->begin())) {
                        //Reaching here means that current path is a prefix
                        //of a kseq - we cannot conclude that it can escape
                        //yet and need to continue to explore paths from
                        //succBB recursively.
                        esc = false;
                        break;
                    }
                }
                if (esc) {
                    return true;
                }
                if (cont_explore) {
                    to_do.insert(succBB);
                }
                cp.pop_back();
            }
            //Recursively continuing the paths.
            for (auto &e : to_do) {
                cp.push_back(e);
                if (_escapeKseq(cp, kseqs)) {
                    return true;
                }
                cp.pop_back();
            }
            //All succs cannot escape.
            return false;
        }

        //Given killer seqs that produce conflicting ret values, this functions tries to
        //further identify the InstLocs that once stepped on, will ineviatably lead to
        //the killer seqs.
        int _getKlocsFromSeqs(CallContext *cctx, std::set<std::vector<BasicBlock*>> &kseqs,
                              std::set<InstLoc*> &klocs) {
            if (!cctx || kseqs.empty()) {
                return -1;
            }
            klocs.clear();
            //Group all the seqs with the same stating BB.
            std::map<BasicBlock*, std::set<const std::vector<BasicBlock*>*>> ksmap;
            for (auto &seq : kseqs) {
                if (seq.empty() || !seq[0]) {
                    continue;
                }
                //Quick path for kloc identification.
                if (seq.size() <= 1) {
                    klocs.insert(InstLoc::getLoc(_pickInstFromBB(seq[0]),cctx,true));
                    continue;
                }
                ksmap[seq[0]].insert(&seq);
            }
            //Method: if a BB can reach the return w/o following any paths in the killing seqs,
            //then this BB is not a killer loc, yes otherwise.
            for (auto &e : ksmap) {
                BasicBlock *sb = e.first;
                std::vector<BasicBlock*> path;
                path.push_back(sb);
                if (!_escapeKseq(path, e.second)) {
                    klocs.insert(InstLoc::getLoc(_pickInstFromBB(sb),cctx,true));
                }
            }
            return 0;
        }

        //The conditional is about a function return value, we need to find the killer
        //InstLocs in that callee that once reached, the callee will return a value
        //to make the desired branch of the conditional ("dst") infeasible.
        int getCondKillerLocsRet(InstLoc *cloc, unsigned dst, std::set<InstLoc*> &klocs) {
            if (!cloc || this->traitCheckRets.find(cloc) == this->traitCheckRets.end()) {
                return 0;
            }
#ifdef DEBUG_ADD_SUPP_LOC
            //dbgs() << "getCondKillerLocsRet(): there are some TraitChecks (regarding ret value) for ";
            //cloc->print_light(dbgs(), true); 
#endif
            klocs.clear();
            for (auto &e0 : this->traitCheckRets[cloc]) {
                CallInst *ci = e0.first;
                assert(ci);
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "getCondKillerLocsRet(): processing the TraitCheck for ret value of: "
                << InstructionUtils::getValueStr(ci) << "\n";
#endif
                // Get the calling context for the callee that produces the return value.
                // Note that there can be multiple of them (e.g., it's an indirect call).
                std::set<CallContext *> callCtxs;
                CallContext::getCalleeCtx(cloc->ctx, *ci, callCtxs);
                if (callCtxs.empty()) {
                    // No callee context found.
#ifdef DEBUG_ADD_SUPP_LOC
                    dbgs() << "getCondKillerLocsRet(): cannot get the callee context of the callsite!\n";
#endif
                    continue;
                }
                for (TraitCheck *tc : e0.second) {
                    assert(tc);
#ifdef DEBUG_ADD_SUPP_LOC
                    dbgs() << "getCondKillerLocsRet(): TraitCheck: ";
                    tc->print(dbgs(), true);
#endif
                    int ec = 0;
                    expr echk = tc->getZ3Expr4Branch(dst, ec);
                    if (ec) {
                        //Failed to obtain the z3 expr for the desired branch.
                        continue;
                    }
#ifdef DEBUG_ADD_SUPP_LOC
                    dbgs() << "getCondKillerLocsRet(): the z3 expr for the desired branch: "
                    << echk.to_string() << "\n";
#endif
                    for (CallContext *cctx : callCtxs) {
                        //Get the killer InstLocs within the callee that once reached, will lead to
                        //return values that can kill the desired branch in the condition check.
                        std::set<InstLoc*> callee_klocs;
                        _getKillerRets(cctx, echk, callee_klocs);
                        klocs.insert(callee_klocs.begin(), callee_klocs.end());
                    }
                }
            }
            return 0;
        }

        //The critical conditional is a phi node merging values from different paths, this case
        //is similar to the return value based cond check (handled by getCondKillerLocsRet()),
        //it's like the callee in that situation is inlined.
        int getCondKillerLocsPHI(InstLoc *cloc, unsigned dst, std::set<InstLoc*> &klocs) {
            if (!cloc || this->traitCheckPHIs.find(cloc) == this->traitCheckPHIs.end()) {
                return 0;
            }
#ifdef DEBUG_ADD_SUPP_LOC
            //dbgs() << "getCondKillerLocsPHI(): there are some TraitChecks (regarding PHI node) for ";
            //cloc->print_light(dbgs(), true);
#endif
            klocs.clear();
            for (auto &e0 : this->traitCheckPHIs[cloc]) {
                PHINode *pi = e0.first;
                if (!pi || !pi->getParent()) {
                    continue;
                }
#ifdef DEBUG_ADD_SUPP_LOC
                dbgs() << "getCondKillerLocsPHI(): processing the TraitCheck for the PHI node: "
                << InstructionUtils::getValueStr(pi) << "\n";
#endif
                for (TraitCheck *tc : e0.second) {
                    assert(tc);
#ifdef DEBUG_ADD_SUPP_LOC
                    dbgs() << "getCondKillerLocsPHI(): TraitCheck: ";
                    tc->print(dbgs(), true);
#endif
                    int ec = 0;
                    expr echk = tc->getZ3Expr4Branch(dst, ec);
                    if (ec) {
                        //Failed to obtain the z3 expr for the desired branch.
                        continue;
                    }
#ifdef DEBUG_ADD_SUPP_LOC
                    dbgs() << "getCondKillerLocsPHI(): the z3 expr for the desired branch: "
                    << echk.to_string() << "\n";
#endif
                    //See whether there are any BBs that once stepped on, will lead to
                    //a specific value selected by the PHI node to kill the desired branch
                    //(i.e., violating echk).
                    std::map<Value*, std::set<std::vector<BasicBlock*>>> openSeqs;
                    std::set<std::vector<BasicBlock*>> kseqs;
                    std::vector<BasicBlock*> seq{pi->getParent()};
                    openSeqs[pi].insert(seq);
                    this->_getKseqs(cloc->ctx, echk, openSeqs, kseqs);
#ifdef DEBUG_ADD_SUPP_LOC
                    dbgs() << "getCondKillerLocsPHI(): #killer seqs: " << kseqs.size() << "\n";
#endif
                    // Identify the killer InstLocs based on the killer sequences.
                    if (!kseqs.empty()) {
                        this->_getKlocsFromSeqs(cloc->ctx, kseqs, klocs);
#ifdef DEBUG_ADD_SUPP_LOC
                        dbgs() << "getCondKillerLocsPHI(): #klocs: " << klocs.size() << "\n";
#endif
                    }
                }
            }
            return 0;
        }
        
        //Given an InstLoc which is a condition check and the No. of the desired branch ("dst"),
        //this function tries to find all the InstLocs that once executed, making the specified
        //branch infeasible (i.e., kills the branch).
        //For example, "a = 1" kills the true branch (No. 0) of "if (!a)".
        int getCondKillerLocs(InstLoc *cloc, unsigned dst, std::set<InstLoc*> &klocs) {
            if (!cloc) {
                return 0;
            }
#ifdef DEBUG_ADD_SUPP_LOC
            dbgs() << "getCondKillerLocs(): check cloc: ";
            cloc->print_light(dbgs(), true);
#endif
            if (this->traitChecks.find(cloc) != this->traitChecks.end()) {
                return getCondKillerLocsObj(cloc, dst, klocs);
            }
            if (this->traitCheckRets.find(cloc) != this->traitCheckRets.end()) {
                return getCondKillerLocsRet(cloc, dst, klocs);
            }
            if (this->traitCheckPHIs.find(cloc) != this->traitCheckPHIs.end()) {
                return getCondKillerLocsPHI(cloc, dst, klocs);
            }
            return 0;
        }

        /***
         * Get the DataLayout for the current module being analyzed.
         * @return pointer to the DataLayout*
         */
        DataLayout* getDataLayout() {
            return this->targetDataLayout;
        }

        /***
         * Get the type size for the provided type.
         * @param currType Type for which size needs to fetched.
         * @return uint64_t representing size of the type.
         */
        uint64_t getTypeSize(Type *currType) {
            if(currType->isSized()) {
                return this->getDataLayout()->getTypeAllocSize(currType);
            }
            return 0;
        }

        /***
         * Get the AliasObject referenced by the currVal.
         *
         * @param currVal Value whose reference needs to be fetched.
         * @param globalObjectCache Map containing values and corresponding
         *                          AliasObject.
         * @return Corresponding AliasObject.
         */
        static AliasObject* getReferencedGlobal(std::vector<llvm::GlobalVariable *> &visitedCache, Value *currVal,
                                                std::map<Value*, AliasObject*> &globalObjectCache) {
            llvm::GlobalVariable *actualGlobal = dyn_cast<llvm::GlobalVariable>(currVal);
            if (actualGlobal == nullptr) {
                // OK, check with stripped.
                Value *strippedVal = currVal->stripPointerCasts();
                actualGlobal = dyn_cast<llvm::GlobalVariable>(strippedVal);
            }
            // Even stripping din't help. Check if this is an instruction and get the first
            // global variable in operand list
            // TODO: a better handling of the ConstantExpr. 
            if (actualGlobal == nullptr && dyn_cast<ConstantExpr>(currVal)) {
                ConstantExpr *targetExpr = dyn_cast<ConstantExpr>(currVal);
                for (unsigned int i = 0; i < targetExpr->getNumOperands(); i++) {
                    Value *currOperand = targetExpr->getOperand(i);
                    llvm::GlobalVariable *globalCheck = dyn_cast<llvm::GlobalVariable>(currOperand);
                    if (globalCheck == nullptr) {
                        // check with strip
                        globalCheck = dyn_cast<llvm::GlobalVariable>(currOperand->stripPointerCasts());
                    }
                    if (globalCheck != nullptr) {
                        actualGlobal = globalCheck;
                        break;
                    }
                    AliasObject *refObj = getReferencedGlobal(visitedCache, currOperand, globalObjectCache);
                    if(refObj != nullptr) {
                        return refObj;
                    }
                }
            }
            //Is it a function?
            if (actualGlobal == nullptr && dyn_cast<Function>(currVal)) {
                Function *targetFunction = dyn_cast<Function>(currVal);
                //NOTE: we assume that all functions that have definitions in the module have already 
                //been added to globalObjectCache (i.e. in "setupGlobals").
                if (globalObjectCache.find((Value*)targetFunction) != globalObjectCache.end()) {
                    return globalObjectCache[(Value*)targetFunction];
                }else {
                    dbgs() << "!!! getReferencedGlobal(): Cannot find the targetFunction in the cache: "
                    << targetFunction->getName().str() << "\n";
                }
            }
            if(actualGlobal != nullptr) {
                //Not a function, neither expr, it's a normal global object pointer.
                return addGlobalVariable(visitedCache, actualGlobal, globalObjectCache);
            }
            return nullptr;
        }

        bool addTraitCheck(InstLoc *loc, AliasObject *obj, long fid, TraitCheck *tc) {
            if (!loc || !obj || !tc) {
                return false;
            }
            this->traitChecks[loc][obj][fid].insert(tc);
            return true;
        }

        bool addTraitCheckRet(InstLoc *loc, CallInst *ci, TraitCheck *tc) {
            if (!loc || !ci || !tc) {
                return false;
            }
            this->traitCheckRets[loc][ci].insert(tc);
            return true;
        }

        bool addTraitCheckPHI(InstLoc *loc, PHINode *pi, TraitCheck *tc) {
            if (!loc || !pi || !tc) {
                return false;
            }
            this->traitCheckPHIs[loc][pi].insert(tc);
            return true;
        }

        /***
         *  Check if the Constant is a constant variable. ie. it uses
         *  some global variables.
         * @param targetConstant Constant to check
         * @return true/false depending on whether the constant
         *         references global variable.
         */
        static bool isConstantVariable(Constant *targetConstant) {
            Function* functionCheck = dyn_cast<Function>(targetConstant);
            if(functionCheck) {
                return true;
            }
            llvm::GlobalVariable *globalCheck = dyn_cast<llvm::GlobalVariable>(targetConstant);
            if(globalCheck) {
                return true;
            }
            ConstantExpr *targetExpr = dyn_cast<ConstantExpr>(targetConstant);
            if(targetExpr) {
                return true;
            }
            return false;
        }

        /***
         *  Get the global object from variable initializers.
         * @param constantType Type of the constant.
         * @param targetConstant Constant for which AliasObject needs to be created.
         * @param globalObjectCache Cache containing value to AliasObject.
         * @return Alias Object corresponding to the initializer.
         */
        static AliasObject* getGlobalObjectFromInitializer(std::vector<llvm::GlobalVariable *> &visitedCache,
                                                           Constant *targetConstant,
                                                           std::map<Value*, AliasObject*> &globalObjectCache) {
            if (!targetConstant || !targetConstant->getType() || !dyn_cast<ConstantAggregate>(targetConstant)) {
                return nullptr;
            }
            ConstantAggregate *constA = dyn_cast<ConstantAggregate>(targetConstant);
            Type* constantType = targetConstant->getType();
            AliasObject *glob = new GlobalObject(targetConstant, constantType);
            //hz: this can handle both the struct and sequential type.
            for (unsigned int i = 0; i < constA->getNumOperands(); ++i) {
                Constant *constCheck = constA->getOperand(i);
                if (!constCheck) {
                    continue;
                }
                AliasObject *currFieldObj = nullptr;
                if (isConstantVariable(constCheck)) {
                    // OK, the field is initialized w/ a global object pointer, now get that pointee global object.
                    currFieldObj = getReferencedGlobal(visitedCache, constCheck, globalObjectCache);
                    //Update the field point-to record.
                    if (currFieldObj != nullptr) {
                        //Since this is the global object initialization, the InstLoc is nullptr.
                        glob->addObjectToFieldPointsTo(i, currFieldObj, nullptr);
                    }
                } else if (dyn_cast<ConstantAggregate>(constCheck)) {
                    // This is an embedded struct...
                    currFieldObj = getGlobalObjectFromInitializer(visitedCache, constCheck, globalObjectCache);
                    // Update the embed object record.
                    if (currFieldObj != nullptr) {
                        glob->setEmbObj(i, currFieldObj, true);
                    }
                } else {
                    // This is possibly an integer field initialization, we can just skip.
                    continue; 
                }
            }
            return glob;
        }

        //Decide whether we need to create a GlobalObject for a certain GlobalVariable.
        static bool toCreateObjForGV(llvm::GlobalVariable *globalVariable) {
            if (!globalVariable) {
                return false;
            }
            Type *ty = globalVariable->getType();
            // global variables are always pointers
            if (!ty || !ty->isPointerTy()) {
                return false;
            }
            ty = ty->getPointerElementType();
            // Don't create GlobalObject for certain types (e.g. str pointer).
            Type *ety = nullptr;
            if (InstructionUtils::isSeqTy(ty, &ety)) {
                if (InstructionUtils::isPrimitiveTy(ety) || InstructionUtils::isPrimitivePtr(ety)) {
                    return false;
                }
            }
            //Filter by name.
            std::string bls[] = {".str.",".descriptor"};
            if (globalVariable->hasName()) {
                std::string n = globalVariable->getName().str();
                for (auto &s : bls) {
                    if (n.find(s) != std::string::npos) {
                        return false;
                    }
                }
            }
            return true;
        }

        /***
         * Add global variable into the global state and return corresponding AliasObject.
         *
         * Handles global variables in a rather complex way.
         * A smart person should implement this in a better way.
         *
         *
         * @param globalVariable Global variable that needs to be added.
         * @param globalObjectCache Cache of Values to corresponding AliasObject.
         * @return AliasObject corresponding to the global variable.
         */
        static AliasObject* addGlobalVariable(std::vector<llvm::GlobalVariable*> &visitedCache,
                                              llvm::GlobalVariable *globalVariable,
                                      std::map<Value*, AliasObject*> &globalObjectCache) {

            if (!globalVariable) {
                return nullptr;
            }
            if(std::find(visitedCache.begin(), visitedCache.end(), globalVariable) != visitedCache.end()) {
#ifdef DEBUG_GLOBALS
                dbgs() << "Cycle Detected for: " << InstructionUtils::getValueStr(globalVariable) << "\n";
#endif
                return nullptr;
            }
            Value *objectCacheKey = dyn_cast<Value>(globalVariable);
            Type *baseType = globalVariable->getType();
            // global variables are always pointers
            if (!baseType || !baseType->isPointerTy()) {
                return nullptr;
            }
            Type *objType = baseType->getPointerElementType();
            //Don't create the GlobalObject for certain GVs.
            if (!toCreateObjForGV(globalVariable)) {
                return nullptr;
            }
            // if its already processed? Return previously created object.
            if(globalObjectCache.find(objectCacheKey) != globalObjectCache.end()) {
                return globalObjectCache[objectCacheKey];
            }
            AliasObject *toRet = nullptr;
            visitedCache.push_back(globalVariable);
            // This is new global variable.
            // next check if it has any initializers.
            if (globalVariable->hasInitializer()) {
                Constant *targetConstant = globalVariable->getInitializer();
                toRet = getGlobalObjectFromInitializer(visitedCache, targetConstant, globalObjectCache);
            }
            if(toRet == nullptr) {
                // OK, the global variable has no initializer.
                // Just create a default object.
                toRet = new GlobalObject(globalVariable, objType);
            }
            //Update the global pto records.
            if (toRet != nullptr) {
                //TODO: confirm that the global variable is const equals to the pointee object is also const.
                toRet->is_const = globalVariable->isConstant();
                //hz: since this is the pre-set pto for gv, there is no calling context. 
                std::set<PointerPointsTo*> *newPointsTo = new std::set<PointerPointsTo*>();
                PointerPointsTo *pointsToObj = new PointerPointsTo(globalVariable, toRet, 0, InstLoc::getLoc(globalVariable,nullptr), false);
                newPointsTo->insert(newPointsTo->end(), pointsToObj);
                assert(GlobalState::globalVariables.find(globalVariable) == GlobalState::globalVariables.end());
                GlobalState::globalVariables[globalVariable] = newPointsTo;
                toRet->addPointerPointsTo(pointsToObj);
                //dbgs() << "Adding:" << *globalVariable << " into cache\n";
                // make sure that object cache doesn't already contain the object.
                assert(globalObjectCache.find(objectCacheKey) == globalObjectCache.end());
                // insert into object cache.
                globalObjectCache[objectCacheKey] = toRet;
                // Make sure that we have created a pointsTo information for globals.
                assert(GlobalState::globalVariables.find(globalVariable) != GlobalState::globalVariables.end());
                assert(GlobalState::globalVariables[globalVariable] != nullptr);
            }
            visitedCache.pop_back();
            return toRet;
        }

        /***
         * Add global function into GlobalState.
         * @param currFunction Function that needs to be added.
         * @param globalObjectCache Map of values and corresponding AliasObject.
         */
        static void addGlobalFunction(Function *currFunction, std::map<Value*, AliasObject*> &globalObjectCache) {
            // add to the global cache, only if there is a definition.
            if(!currFunction->isDeclaration()) {
                std::set<PointerPointsTo*> *newPointsTo = new std::set<PointerPointsTo*>();
                GlobalObject *glob = new GlobalObject(currFunction);
                PointerPointsTo *pointsToObj = new PointerPointsTo(currFunction, glob, 0, InstLoc::getLoc(currFunction,nullptr), false);
                newPointsTo->insert(newPointsTo->end(), pointsToObj);

                GlobalState::globalVariables[currFunction] = newPointsTo;
                globalObjectCache[currFunction] = glob;
            }
        }

        /***
         * Add loop exit blocks for the provided function.
         * @param targetFunction Pointer to the function for which the loop exit block needs to be added.
         * @param allExitBBs List of the basicblocks to be added
         */
        static void addLoopExitBlocks(Function *targetFunction, SmallVector<BasicBlock *, 1000> &allExitBBs) {
            if(loopExitBlocks.find(targetFunction) == loopExitBlocks.end()) {
                loopExitBlocks[targetFunction] = new std::set<BasicBlock*>();
            }
            std::set<BasicBlock*> *toAddList;
            toAddList = loopExitBlocks[targetFunction];
            toAddList->insert(allExitBBs.begin(), allExitBBs.end());
        }

        /***
         * Get all loop exit basic blocks for the provided function.
         * @param targetFunction Target function for which the exit blocks needs to be fetched.
         * @return pointer to set of all loop exit basic blocks for the provided function.
         */
        static std::set<BasicBlock*> * getLoopExitBlocks(Function *targetFunction) {
            if(loopExitBlocks.find(targetFunction) != loopExitBlocks.end()) {
                return loopExitBlocks[targetFunction];
            }
            return nullptr;
        }


        void diagnoseUnseenCtx(std::vector<Instruction*> *callSites) {
            //In theory all contexts have been analyzed in the main analysis phase, it's impossible that
            //in bug detection phase we have an unseen context. If this happens, we really need a thorough inspection...
            if (this->analysis_phase > 2) {
                dbgs() << "!!!!! getContext(): In bug detection phase we have an unseen calling context:\n";
                for (Instruction *inst : *callSites) {
                    InstructionUtils::printInst(inst,dbgs());
                }
                dbgs() << "We now have " << CallContext::dir.size() << " ctx available, try to find a nearest one...\n";
                //(1) Longest common prefix, and (2) most matched insts.
                std::vector<Instruction*> *lcp = nullptr, *mmi = nullptr;
                int nlcp = 0, nmmi = 0;
                for (auto curr_a : CallContext::dir) {
                    for (auto curr_b : curr_a.second) {
                        for (auto curr_c : curr_b.second) {
                            std::vector<Instruction *> *c = curr_c->callSites;
                            if (!c) {
                                continue;
                            }
                            bool pr = true;
                            int nl = 0, nm = 0;
                            for (int i = 0; i < callSites->size() && i < c->size(); ++i) {
                                if ((*c)[i] == (*callSites)[i]) {
                                    if (pr) {
                                        ++nl;
                                    }
                                    ++nm;
                                } else {
                                    pr = false;
                                }
                            }
                            if (nl > nlcp) {
                                nlcp = nl;
                                lcp = c;
                            }
                            if (nm > nmmi) {
                                nmmi = nm;
                                mmi = c;
                            }
                        }
                    }
                }
                if (lcp) {
                    dbgs() << "==The candidate w/ longest common prefix:\n";
                    for (Instruction *inst : *lcp) {
                        InstructionUtils::printInst(inst,dbgs());
                    }
                }
                if (mmi) {
                    dbgs() << "==The candidate w/ most matched insts:\n";
                    for (Instruction *inst : *mmi) {
                        InstructionUtils::printInst(inst,dbgs());
                    }
                }
            }
        }

        // Get the context for the provided instruction at given call sites.
        CallContext* getContext(std::vector<Instruction*> *callSites) {
            if (!callSites || callSites->empty()) {
                if (this->analysis_phase > 2) {
                    dbgs() << "!!! getContext(): Null callSites received in the bug detection phase!\n";
                }
                return nullptr;
            }
            CallContext *ctx = CallContext::getContext(callSites,false);
            if (ctx) {
                return ctx;
            }
            //We cannot get a matching calling context, which is abnormal in
            //bug detection phase.
            if (this->analysis_phase > 2) {
                this->diagnoseUnseenCtx(callSites);
            }
            return nullptr;
        }


        /***
         *  Get or create context at the provided list of callsites,
         *  with corresponding pointsto and taint information.
         *
         * @param callSites list of call sites for the target context.
         * @param targetInfo Points-To info as std::set<PointerPointsTo*>*>*
         * @param targetTaintInfo Taint into as std::map<Value *, std::set<TaintFlag*>*> *
         * @return Target context updated with the provided information.
         *
         */
        CallContext* getOrCreateContext(std::vector<Instruction*> *callSites, std::map<Value*,
                std::set<PointerPointsTo*>*> *targetInfo = nullptr, std::map<Value *, std::set<TaintFlag*>*> *targetTaintInfo = nullptr) {

            bool created = false;
            CallContext* ctx = CallContext::getContext(callSites,true,&created);
            if (created) {
                // We have encountered with an unseen calling context, we need to
                // set up its points-to and taint information.
                // create new points to information.
                std::map<Value*, std::set<PointerPointsTo*>*> *newInfo = new std::map<Value*, std::set<PointerPointsTo*>*>();
                if (targetInfo != nullptr) {
                    newInfo->insert(targetInfo->begin(), targetInfo->end());
                } else {
                    //To copy global pto records to every calling context can lead to high
                    //memory consumption especially for large bc files with lots of global
                    //variables. Since top-level global variables are also in SSA form
                    //(e.g., their pto records will only be assigned once in the init phase)
                    //and the memory fields they point to also have their own pto records
                    //with context-sensitive propagating InstLocs, it should be safe to only
                    //keep a central copy of global pto records (i.e., "GlobalState::globalVariables"). 
                    /*
                    // Add all global variables in to the context.
                    newInfo->insert(GlobalState::globalVariables.begin(), GlobalState::globalVariables.end());
                    */
                }
                pointToInformation[ctx] = newInfo;

                // create taint info for the newly created context.
                /*
                std::map<Value *, std::set<TaintFlag*>*> *newTaintInfo = new std::map<Value *, std::set<TaintFlag*>*>();
                if(targetTaintInfo != nullptr) {
                    newTaintInfo->insert(targetTaintInfo->begin(), targetTaintInfo->end());
                }
                taintInformation[ctx] = newTaintInfo;
                */
            }
            return ctx;
        }

        void copyPointsToInfo(CallContext *targetContext) {
            // Make a shallow copy of points to info for the current context.
            std::map<Value *, std::set<PointerPointsTo*>*> *currInfo = pointToInformation[targetContext];

            // we need to make a shallow copy of currInfo
            std::map<Value *, std::set<PointerPointsTo*>*> *newInfo = new std::map<Value *, std::set<PointerPointsTo*>*>();
            newInfo->insert(currInfo->begin(), currInfo->end());

            pointToInformation[targetContext] = newInfo;
        }

        /***
         * Get all points to information at the provided context i.e., list of call sites.
         * @param callSites target context: List of call-sites
         * @return PointsTo information as std::map<Value *, std::set<PointerPointsTo*>*>*
         */
        std::map<Value *, std::set<PointerPointsTo*>*> *getPointsToInfo(CallContext *ctx) {
            if (!ctx || !pointToInformation.count(ctx)) {
                return nullptr;
            }
            return pointToInformation[ctx];
        }

        std::map<Value*, Constraint*> *getCtxConstraints(CallContext *ctx) {
            return &(this->constraintInformation[ctx]);
        }

        Constraint *getConstraints(CallContext *ctx, Value *v, bool create = true) {
            if (!v) {
                return nullptr;
            }
            if (this->constraintInformation.find(ctx) != this->constraintInformation.end() &&
                this->constraintInformation[ctx].find(v) != this->constraintInformation[ctx].end()) {
                Constraint *r = this->constraintInformation[ctx][v];
                if (r) {
                    //Got the existing Constraint.
                    return r;
                }
            }
            //This means there is no existing constraint, create one if specified.
            if (create) {
                Constraint *r = new Constraint(v);
                this->constraintInformation[ctx][v] = r;
                return r;
            }
            return nullptr;
        }

        //The difference with "getConstraints()" is that this function
        //(1) doesn't try to create any Constraints if there are not any;
        //(2) if no constraints are present for "ctx", try to get the ctx-free constraints.
        //Note that due to the logic of our path analysis, ctx-specific constraints.
        //already include all the constraints in the ctx-free one.
        Constraint *getAvailableConstraints(CallContext *ctx, Value *v) {
            Constraint *c = this->getConstraints(ctx, v, false);
            if (c) {
                return c;
            }
            if (ctx) {
                return this->getConstraints(nullptr, v, false);
            }
            return nullptr;
        }

        bool setConstraints(CallContext *ctx, Value *v, Constraint *c) {
            if (!v || !c) {
                return false;
            }
            this->constraintInformation[ctx][v] = c;
            return true;
        }

        //Insert the provided dead BBs to the current records.
        void updateDeadBBs(CallContext *ctx, std::set<BasicBlock*> &bbs) {
            if (bbs.empty()) {
                return;
            }
            (this->deadBBs)[ctx].insert(bbs.begin(),bbs.end());
            return;
        }

        std::set<BasicBlock*> *getDeadBBs(CallContext *ctx) {
            if (this->deadBBs.find(ctx) != this->deadBBs.end()) {
                return &((this->deadBBs)[ctx]);
            }
            return nullptr;
        }

        //NOTE: we need to consider both the ctx-specific and ctx-free dead BBs.
        bool isDeadBB(CallContext *ctx, BasicBlock *bb) {
            std::set<BasicBlock*> *dbbs = this->getDeadBBs(ctx);
            if (dbbs && dbbs->find(bb) != dbbs->end()) {
                return true;
            }
            //Also consider the ctx-free dead BBs.
            if (ctx) {
                dbbs = this->getDeadBBs(nullptr);
                if (dbbs && dbbs->find(bb) != dbbs->end()) {
                    return true;
                }
            }
            return false;
        }

        // Taint Handling functions

        /***
         * get all taint information at the provided context i.e., list of call sites
         * @param callSites target context: List of call-sites
         * @return Taint information as: std::map<Value *, std::set<TaintFlag*>*>*
         */
        std::map<Value *, std::set<TaintFlag*>*>* getTaintInfo(CallContext *ctx) {
            if(ctx != nullptr && taintInformation.count(ctx)) {
                return taintInformation[ctx];
            }
            return nullptr;
        };

        int getAllObjsForPath(std::vector<TypeField*> *p, std::set<AliasObject*> &res) {
            if (!p || !p->size()) {
                return 0;
            }
            std::set<AliasObject*> stageObjs, nextObjs;
            stageObjs.insert((AliasObject*)((*p)[0]->priv));
            int i = 0;
            for (;i < p->size() - 1; ++i) {
                TypeField *tf = (*p)[i];
                TypeField *ntf = (*p)[i+1];
                if (!tf || !ntf || !tf->priv || !ntf->priv) {
                   break;
                }
                if (stageObjs.empty()) {
                    break;
                }
                nextObjs.clear();
                //First decide the relationship between current typefield and the next one (e.g. point-to or embed)
                if (((AliasObject*)(ntf->priv))->parent == tf->priv) {
                    //Embed, we need to get all embedded objects at the same field of the objs in "stageObjs".
                    for (AliasObject *so : stageObjs) {
                        if (so && so->embObjs.find(tf->fid) != so->embObjs.end()) {
                            AliasObject *no = so->embObjs[tf->fid];
                            if (InstructionUtils::same_types(no->targetType,ntf->ty)) {
                                nextObjs.insert(no);
                            }
                        }
                    }
                }else {
                    //Point-to, need to find all pointee objects of the same field of the objs in "stageObjs".
                    for (AliasObject *so : stageObjs) {
                        if (!so || so->pointsTo.find(tf->fid) == so->pointsTo.end()) {
                            continue;
                        }
                        for (ObjectPointsTo *pto : so->pointsTo[tf->fid]) {
                            if (!pto || !pto->targetObject) {
                                continue;
                            }
                            if (pto && pto->targetObject && (pto->dstfieldId == 0 || pto->dstfieldId == ntf->fid) && 
                                InstructionUtils::same_types(pto->targetObject->targetType,ntf->ty)) {
                                nextObjs.insert(pto->targetObject);
                            }
                        }
                    }
                }
                stageObjs.clear();
                stageObjs.insert(nextObjs.begin(),nextObjs.end());
            }
            //The leaf obj is always in the result set.
            TypeField *lastTf = (*p)[p->size()-1];
            if (lastTf && lastTf->priv) {
                res.insert((AliasObject*)(lastTf->priv));
            }
            //Add the inferred equivelant objects by path.
            if (i >= p->size() - 1) {
                res.insert(stageObjs.begin(),stageObjs.end());
            }
            return 0;
        }

        //Ret: 1 : eqv, 0 : not eqv, -1 : unknown
        int isEqvObj(AliasObject *o0, AliasObject *o1) {
            if (!o0 != !o1) {
                return 0;
            }
            if (!o0) {
                return 1;
            }
            for (std::set<AliasObject*> *cls : DRCHECKER::eqObjs) {
                if (!cls) {
                    continue;
                }
                if (cls->find(o0) != cls->end()) {
                    //Found the equivelant class in the cache...
                    return (cls->find(o1) != cls->end() ? 1 : 0);
                }
                if (cls->find(o1) != cls->end()) {
                    //Found the equivelant class in the cache...
                    return (cls->find(o0) != cls->end() ? 1 : 0);
                }
            }
            return -1;
        }

        //Due to our current multi-entry analysis logic, each entry function will be analyzed independently (e.g. it will not
        //re-use the AliasObject created by other entry functions, instead it will created its own copy), so here we need to
        //identify all potentially identical objects to the provided one, which ensures that our taint chain construction is
        //sound.
        int getAllEquivelantObjs(AliasObject *obj, std::set<AliasObject*> &res) {
            if (!obj) {
                return 0;
            }
            //Always includes itself.
            res.insert(obj);
            //Look up the cache.
            std::set<AliasObject*> *eqcls = nullptr;
            for (std::set<AliasObject*> *cls : DRCHECKER::eqObjs) {
                if (cls && cls->find(obj) != cls->end()) {
                    //Found the equivelant class in the cache...
                    eqcls = cls;
                    break;
                }
            }
            if (eqcls == nullptr) {
                //No equivelant class found in the cache, need to do the dirty work now...
                //By default the obj itself is in its own equivelant class.
#ifdef DEBUG_CONSTRUCT_TAINT_CHAIN
                dbgs() << "getAllEquivelantObjs(): identify eq objs for: " << (const void*)obj << "\n";
#endif
                eqcls = new std::set<AliasObject*>();
                eqcls->insert(obj);
                DRCHECKER::eqObjs.insert(eqcls);
                //First we need to collect all access paths to current object.
                //TODO: what if there is a pointsFrom obj who points to a non-zero field in "obj"?
                std::set<std::vector<TypeField*>*> *hty = getObjHierarchyTy(obj,0);
#ifdef DEBUG_CONSTRUCT_TAINT_CHAIN
                dbgs() << "getAllEquivelantObjs(): #accessPaths: " << (hty ? hty->size() : 0) << "\n";
#endif
                //Then based on each access path, we identify all the equivelant objects (i.e. those w/ the same access path).
                if (hty && hty->size()) {
                    for (std::vector<TypeField*> *ap : *hty) {
                        if (!ap || !ap->size()) {
                            continue;
                        }
                        getAllObjsForPath(ap,*eqcls);
                    }
                }
            }
            for (AliasObject *co : *eqcls) {
                //Objects bearing the same path may still have different types (e.g. those ->private pointers),
                //so it's necessary to make another type-based filtering here.
                if (!InstructionUtils::same_types(obj->targetType,co->targetType)) {
                    continue;
                }
                //If the target obj is a dummy one, then it can match any other object (dummy or not), 
                //otherwise, it can only match other dummy objects (i.e. two real objects cannot match).
                if (obj->auto_generated || co->auto_generated) {
                    res.insert(co);
                }
            }
            return 0;
        }

        //Return "-1" if no duplication, otherwise the index of the duplicated node.
        static int in_hierarchy_history(AliasObject *obj, long field, std::vector<std::pair<long, AliasObject*>>& history, bool to_add) {
            /*
            auto to_check = std::make_pair(field, obj);
            */
            //To prevent the potential chain explosion caused by recursive data structures (e.g., linked list, red-black tree) and
            //other issues, our duplication detection is based on the following logics:
            //(1) As long as two nodes in the chain have the same obj id, call it a duplication (i.e., ignore the field id).
            //(2) Exclude the case where multiple recursive structure related nodes (e.g., list_head) appear in the chain.
#ifdef CONFINE_RECUR_STRUCT
            std::string nty;
            if (obj && obj->targetType) {
                nty = InstructionUtils::isRecurTy(obj->targetType);
            }
#endif
            for (int i = history.size() - 1; i >= 0; --i) {
                AliasObject *hobj = history[i].second;
                if (hobj == obj) {
                    return i;
                }
#ifdef CONFINE_RECUR_STRUCT
                if (!nty.empty() && hobj) {
                    std::string hty = InstructionUtils::getTypeName(hobj->targetType);
                    InstructionUtils::trim_num_suffix(&hty);
                    if (hty == nty) {
                        return i;
                    }
                }
#endif
            }
            if (to_add) {
                auto to_check = std::make_pair(field, obj);
                history.push_back(to_check);
            }
            return -1;
        }

        //NOTE: in this function we use quite some heuristics.
        static bool valid_history(std::vector<std::pair<long, AliasObject*>>& history) {
            if (history.size() < 4) {
                return true;
            }
            //Ok it's a long history, if it also contains some same typed object types, let's say it's invalid.
            std::set<Type*> tys;
            for (auto &e : history) {
                AliasObject *obj = e.second;
                if (!obj) {
                    return false;
                }
                if (tys.find(obj->targetType) != tys.end()) {
                    return false;
                }
                tys.insert(obj->targetType);
            }
            return true;
        }

        typedef int (*traverseHierarchyCallback)(std::vector<std::pair<long, AliasObject*>>& chain, int recur);

        //Visit every object hierarchy chain ending w/ field "fid" of "obj", for each chain, invoke the passed-in callback
        //to enable some user-defined functionalities.
        static int traverseHierarchy(AliasObject *obj, long field, int layer, std::vector<std::pair<long, AliasObject*>>& history, 
                                     traverseHierarchyCallback cb = nullptr) {
#ifdef DEBUG_HIERARCHY
            dbgs() << layer << " traverseHierarchy(): " << (obj ? InstructionUtils::getTypeName(obj->targetType) : "") 
            << " | " << field << " ID: " << (const void*)obj << "\n";
#endif
            if (!obj) {
#ifdef DEBUG_HIERARCHY
                dbgs() << layer << " traverseHierarchy(): null obj.\n";
#endif
                return 0;
            }
            //TODO: is it really ok to exclude the local objects?
            if (obj->isFunctionLocal()) {
                //We're not interested in function local variables as they are not persistent.
#ifdef DEBUG_HIERARCHY
                dbgs() << layer << " traverseHierarchy(): function local objs.\n";
#endif
                return 0;
            }
            int dind = in_hierarchy_history(obj,field,history,true);
            if (dind >= 0) {
                //Exists in the history obj chain, should be a loop..
#ifdef DEBUG_HIERARCHY
                dbgs() << layer << " traverseHierarchy(): Exists in the obj chain..\n";
#endif
                if (cb) {
                    (*cb)(history,dind);
                }
                return 1;
            }
            if (!valid_history(history)) {
                //The history is too long or contains some duplicated elements (maybe due to the FP in static analysis),
                //so we decide to stop here...
#ifdef DEBUG_HIERARCHY
                dbgs() << layer << " traverseHierarchy(): Too long a history, unlikely to be real, stop..\n";
#endif
                if (cb) {
                    (*cb)(history,-1);
                }
                history.pop_back();
                return 1;
            }
            int r = 0;
            if (obj->parent && obj->parent->embObjs.find(obj->parent_field) != obj->parent->embObjs.end() 
                && obj->parent->embObjs[obj->parent_field] == obj) {
                //Current obj is embedded in another obj.
#ifdef DEBUG_HIERARCHY
                dbgs() << layer << " traverseHierarchy(): find a host obj that embeds this one..\n";
#endif
                r += traverseHierarchy(obj->parent,obj->parent_field,layer+1,history,cb);
            }
            if (!obj->pointsFrom.empty()) {
                //Current obj may be pointed to by a field in another obj.
                for (auto &x : obj->pointsFrom) {
                    AliasObject *srcObj = x.first;
                    if (!srcObj) {
                        continue;
                    }
                    std::set<long> fids;
                    int dcnt = 0;
                    for (ObjectPointsTo *y : x.second) {
                        if (!y || y->targetObject != obj || (y->dstfieldId != 0 && y->dstfieldId != field)) {
                            continue;
                        }
                        if (fids.find(y->fieldId) != fids.end()) {
                            dbgs() << "PointsFrom of " << (const void*)obj << " dup: " << (const void*)(srcObj) << "|" << y->fieldId 
                            << " #" << ++dcnt << "\n";
                            continue;
                        }
                        fids.insert(y->fieldId);
#ifdef DEBUG_HIERARCHY
                        dbgs() << layer << " traverseHierarchy(): find a host object that can point to this one...\n";
#endif
                        r += traverseHierarchy(srcObj,y->fieldId,layer+1,history,cb);
                    }
                }
            }
            if (!r) {
                //This means current object is the root of the hierarchy chain, we should invoke the callback for this chain.
                if (cb) {
                    (*cb)(history,-1);
                }
                r = 1;
            }
            history.pop_back();
            return r; 
        }

        static int hierarchyStrCb(std::vector<std::pair<long, AliasObject*>>& chain, int recur = -1) {
            if (chain.empty()) {
                return 0;
            }
            std::string s("");
            if (recur >= 0) {
                s += "(";
                s += std::to_string(chain.size() - recur - 1);
                s += ")<->";
            }
            for (int i = chain.size() - 1; i >= 0; --i) {
                long fid = chain[i].first;
                AliasObject *obj = chain[i].second;
                if (obj) {
                    s += (InstructionUtils::getTypeName(obj->targetType) + ":" + std::to_string(fid));
                    if (i > 0) {
                        //Decide the relationship between current obj and the next obj in the chain (e.g. embed or point-to).
                        if (chain[i-1].second && chain[i-1].second->parent == obj) {
                            s += ".";
                        }else {
                            s += "->";
                        }
                    }
                }
            }
            if (s.size()) {
                DRCHECKER::hstrs.insert(s);
            }
            return 0;
        }

        static bool inHty(std::vector<TypeField*> *tys) {
            if (!tys || tys->empty()) {
                return false;
            }
            for (auto &x : DRCHECKER::htys) {
                if (!x || x->size() < tys->size()) {
                    continue;
                }
                int i = x->size(), j = tys->size();
                while(--j >= 0 && --i >= 0) {
                    TypeField *tf0 = (*x)[i];
                    TypeField *tf1 = (*tys)[j];
                    if (!tf0 != !tf1) {
                        break;
                    }
                    if (tf0 && (tf0->priv != tf1->priv || tf0->fid != tf1->fid)) {
                        break;
                    }
                }
                if (j < 0) {
                    return true;
                }
            }
            return false;
        }

        static int hierarchyTyCb(std::vector<std::pair<long, AliasObject*>>& chain, int recur = -1) {
            if (chain.empty()) {
                return 0;
            }
            //If there is self-recursion in the chain, our policy is to delete the recursive part (e.g., the chain between two same nodes)
            int i = (recur >= 0 ? recur : chain.size() - 1);
            //Construct the TypeField chain.
            std::vector<TypeField*> *tys = new std::vector<TypeField*>();
#ifdef CALC_HIERARCHY_HASH
            std::string sig;
#endif
            while (i >= 0) {
                long fid = chain[i].first;
                AliasObject *obj = chain[i].second;
                if (obj) {
                    TypeField *currTf = new TypeField(obj->targetType,fid,(void*)obj);
                    tys->push_back(currTf);
#ifdef CALC_HIERARCHY_HASH
                    sig += std::to_string((long)obj);
                    sig += "_";
                    sig += std::to_string(fid);
                    sig += "_";
#endif
                }else {
                    delete(tys);
                    return 0;
                }
                --i;
            }
            if (tys->size() > 0) {
                //Previously we use "inHty" to to the deduplication but it seems very slow.
#ifdef CALC_HIERARCHY_HASH
                std::hash<std::string> str_hash;
                size_t h = str_hash(sig);
                //Before inserting to htys, one thing to note is we may have a duplicated chain on file already if "recur >= 0", since
                //in that case we only take a part of the original chain. Check it.
                if (recur < 0 || (DRCHECKER::chainHash.find(h) == DRCHECKER::chainHash.end())) {
                    DRCHECKER::htys.insert(tys);
                    DRCHECKER::chainHash.insert(h);
                }
#else
                DRCHECKER::htys.insert(tys);
#endif
            }else {
                delete(tys);
            }
            return 0;
        }

        //A wrapper of getHierarchyStr() w/ a cache.
        static std::set<std::string> *getObjHierarchyStr(AliasObject *obj, long fid) {
            static std::map<AliasObject*,std::map<long,std::set<std::string>*>> cache;
            if (!obj) {
                return nullptr;
            }
            if (cache.find(obj) == cache.end() || cache[obj].find(fid) == cache[obj].end()) {
                std::vector<std::pair<long, AliasObject*>> history;
                history.clear();
                DRCHECKER::hstrs.clear();
                traverseHierarchy(obj, fid, 0, history, hierarchyStrCb);
                cache[obj][fid] = new std::set<std::string>(DRCHECKER::hstrs);
            }
            return cache[obj][fid];
        }

        static void printHtys() {
            dbgs() << "---------[ST] Hierarchy Chain (" << DRCHECKER::htys.size() << ")---------\n";
            for (auto &x : DRCHECKER::htys) {
                if (!x) {
                    continue;
                }
                for (int i = 0; i < x->size(); ++i) {
                    TypeField *tf = (*x)[i];
                    if (tf) {
                        dbgs() << (const void*)(tf->priv) << " " << InstructionUtils::getTypeName(tf->ty) << "|" << tf->fid;
                    }else {
                        dbgs() << "Null TypeField";
                    }
                    if (i < x->size() - 1) {
                        TypeField *ntf = (*x)[i+1];
                        if (ntf && ntf->priv && tf && ((AliasObject*)(ntf->priv))->parent == tf->priv) {
                            dbgs() << " . ";
                        }else {
                            dbgs() << " -> ";
                        }
                    }
                }
                dbgs() << "\n";
            }
            dbgs() << "---------[ED] Hierarchy Chain (" << DRCHECKER::htys.size() << ")---------\n";
        }

        //A wrapper of getHierarchyTy() w/ a cache.
        static std::set<std::vector<TypeField*>*> *getObjHierarchyTy(AliasObject *obj, long fid) {
            static std::map<AliasObject*,std::map<long,std::set<std::vector<TypeField*>*>*>> cache;
            if (!obj) {
                return nullptr;
            }
            if (cache.find(obj) == cache.end() || cache[obj].find(fid) == cache[obj].end()) {
                auto t0 = InstructionUtils::getCurTime(nullptr);
                std::vector<std::pair<long, AliasObject*>> history;
                history.clear();
                for (auto &x : DRCHECKER::htys) {
                    delete(x);
                }
                DRCHECKER::htys.clear();
                DRCHECKER::chainHash.clear();
                traverseHierarchy(obj, fid, 0, history, hierarchyTyCb);
                cache[obj][fid] = new std::set<std::vector<TypeField*>*>();
                for (auto &x : DRCHECKER::htys) {
                    std::vector<TypeField*> *vtf = new std::vector<TypeField*>(*x);
                    cache[obj][fid]->insert(vtf);
                }
                dbgs() << "getObjHierarchyTy(): enumeration done in: ";
                InstructionUtils::getTimeDuration(t0,&dbgs());
#ifdef PRINT_HIERARCHY_CHAIN
                printHtys();
#endif
            }
            return cache[obj][fid];
        }

        void printCurTime() {
            auto t_now = std::chrono::system_clock::now();
            std::time_t now_time = std::chrono::system_clock::to_time_t(t_now);
            dbgs() << std::ctime(&now_time) << "\n";
        }

        //Get surrounding locks for the specific InstLoc "loc", fill in the locks in
        //"res": lock -> set of paired unlocks for this "loc".
        int getLock4Loc(InstLoc *loc, std::map<LockInfo*,std::set<LockInfo*>> &res) {
            if (!loc) {
                return 0;
            }
            res.clear();
            for (LockInfo *lock : this->locks) {
                assert(lock && "Null lock!!");
                assert(lock->loc && "Null lock->loc!!");
                //A heuristic here: it's unlikely that the lock/unlock are in different same-level callees,
                //e.g., A() calls B() and B() puts the lock(), then A() calls C() and C() performs unlock()... 
                //That's to say, the lock's calling context should prefix that of the unlock.
                //TODO: inspect whether there are exceptions to this heuristic.
                if (lock->loc->isCtxPrefix(loc) < 0) {
                    continue;
                }
                //The lock site should reach the target "loc".
                if (!loc->reachable(lock->loc)) {
                    continue;
                }
                if (!lock->pairs.empty()) {
                    std::set<InstLoc *> blk;
                    blk.insert(lock->loc);
                    for (LockInfo *unlock : lock->pairs) {
                        if (!unlock->loc) {
                            dbgs() << "!!! getLock4Loc(): Null unlock->loc for unlock: " << (const void*)unlock << "\n";
                            continue;
                        }
                        //We still need to ensure that there is a path from "loc"
                        //to the unlock site without encountering the lock site.
                        //NOTE that if we only check "loc" can reach unlock, we can
                        //make mistakes when there is a loop, e.g.,
                        //while(true) {lock(); unlock(); loc; }
                        //In this case, we will wrongly identify a lock pair for "loc".
                        if (unlock->loc->reachable(loc, &blk)) {
                            res[lock].insert(unlock);
                        }
                    }
                } else {
                    //Due to some reasons, the lock entry doesn't have the paired "unlock",
                    //One possible reason: the unlock call is at a depth that exceeds our limit.
                    //To be conservative, we do not contain it in the result, otherwise, we may wrongly
                    //filter out a warning (i.e., FN).
                    //TODO: consider about this.
                }
            }
            return 1;
        }

        //Decide whether two lock entry share the same lock objs, note that different from the same-named member
        //function within LockInfo, in this version we consider the eqv objs to facilitate the cross-entry analysis.
        int sameLockObjs(LockInfo *lk0, LockInfo *lk1) {
            if (!lk0 || !lk1) {
                return 0;
            }
            //First see whether the lock functions are of the same series (e.g., mutex and spin are different), as a quick filter.
            if (lk0->fn != lk1->fn) {
                return 0;
            }
            //Ok, now decide whether the used lock objs are same, considering the eqv objs.
            for (PointerPointsTo *p0 : lk0->objs) {
                if (!p0 || !p0->targetObject) {
                    continue;
                }
                std::map<AliasObject*,EqvObjPair*> eqvObjs;
                p0->targetObject->getEqvObjs(eqvObjs);
                for (PointerPointsTo *p1 : lk1->objs) {
                    if (!p1 || p1->dstfieldId != p0->dstfieldId) {
                        continue;
                    }
                    if (eqvObjs.find(p1->targetObject) != eqvObjs.end()) {
                        return 1;
                    }
                }
            }
            return 0;
        }

        //Decide whether two InstLocs hold any same locks..
        //Currently return 0 if no same locks held.
        int holdSameLocks(InstLoc *loc0, InstLoc *loc1) {
            if (!loc0 || !loc1) {
                return 0;
            }
            std::map<LockInfo*,std::set<LockInfo*>> locks0,locks1;
            this->getLock4Loc(loc0,locks0);
            this->getLock4Loc(loc1,locks1);
            for (auto &e0 : locks0) {
                LockInfo *lk0 = e0.first;
                assert(lk0 && "Null lock!!");
                for (auto &e1 : locks1) {
                    LockInfo *lk1 = e1.first;
                    assert(lk1 && "Null lock!!");
                    if (this->sameLockObjs(lk0,lk1)) {
                        return 1;
                    }
                }
            }
            return 0;
        }

        // Adding vulnerability warning

        /***
         * Add the provided vulnerability warning to the current state indexed by instruction.
         * @param currWarning Vulnerability warning that needs to be added.
         */
        void addVulnerabilityWarningByInstr(VulnerabilityWarning *currWarning) {
            if (!currWarning || !currWarning->targetLoc || !currWarning->targetLoc->inst) {
                return;
            }
            Instruction *targetInstr = dyn_cast<Instruction>(currWarning->targetLoc->inst);
            if (!targetInstr) {
                return;
            }
            std::set<VulnerabilityWarning*> *warningList = nullptr;
            if(warningsByInstr.find(targetInstr) == warningsByInstr.end()) {
                warningsByInstr[targetInstr] = new std::set<VulnerabilityWarning*>();
            }
            warningList = warningsByInstr[targetInstr];

            for(auto a:*warningList) {
                if(a->isSameVulWarning(currWarning)) {
                    return;
                }
            }
            warningList->insert(currWarning);
        }

        /***
         * Add the provided vulnerability warning to the current state.
         * @param currWarning Vulnerability warning that needs to be added.
         */
        void addVulnerabilityWarning(VulnerabilityWarning *currWarning) {
            assert(currWarning != nullptr);
            CallContext* currContext = getContext(currWarning->getCallSiteTrace());
            assert(currContext != nullptr);
            if(allVulnWarnings.find(currContext) == allVulnWarnings.end()) {
                // first vulnerability warning.
                allVulnWarnings[currContext] = new std::set<VulnerabilityWarning*>();
            }
            allVulnWarnings[currContext]->insert(currWarning);
            
            //Dump the warning.
            ////////////////
            dbgs() << "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n";
            currWarning->printWarning(dbgs());
            dbgs() << "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n";
            ////////////////

            this->addVulnerabilityWarningByInstr(currWarning);
        }

        //Decide whether the freed object at the F site comes from a linked list.
        bool _isFromLinkedList(InstLoc *loc, AliasObject *obj, bool is_free = true) {
            if (!loc || !obj) {
                return false;
            }
            // First a quick check to see whether the obj has any field indicating
            // it's a node of a recursive structure.
            if (obj->isRecNode()) {
                return true;
            }
            // The basic idea is to check the loadTag of the pto used for the freed
            // object, we will see whether it's eventually loaded from a linked list
            // node (e.g., struct.list_head).
            std::set<PointerPointsTo*> *ptos = nullptr, uptos;
            if (is_free) {
                ptos = obj->getFreePtos(loc);
            } else {
                obj->getUsePtos(loc,uptos);
                ptos = &uptos;
            }
            if (!ptos || ptos->empty()) {
                return false;
            }
            for (PointerPointsTo *pto : *ptos) {
                if (!pto) {
                    continue;
                }
                if (pto->loadTag.empty()) {
                    //TODO: what if there are no loadTags?
                    return false;
                } else {
                    for (TypeField *tf : pto->loadTag) {
                        assert(tf && tf->v);
                        if (!dyn_cast<LoadInst>(((InstLoc *)(tf->v))->inst)) {
                            continue;
                        }
                        LoadInst *li = dyn_cast<LoadInst>(((InstLoc *)(tf->v))->inst);
                        //Quick match by the load inst signature.
                        if (InstructionUtils::isRecurPtrTy(li->getType()) != "") {
                            return true;
                        }
                        //Not the time to give up, try to match the load-src obj|field.
                        if (tf->priv) {
                            AliasObject *sobj = (AliasObject *)(tf->priv);
                            // This means to get the F obj, we have ever loaded from "sobj"
                            // at the field tf->n (see the loadTag construction in
                            // AliasAnalysisVisitor::visitLoadInst()). If it happens to be
                            // a list_head field (e.g., .next or .prev), we can see that "obj"
                            // is eventually from a linked list.
                            if (InstructionUtils::isRecurTyAtIndex(sobj->targetType, tf->n)) {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

        // Validate the data flow of a seq UAF.
        // Currently implemented filtering logic:
        // (1) check whether the pto record for "obj" at U site will be killed in all
        // paths passing the F site (so that the seq UAF with "obj" is impossible).
        // -- e.g.,
        // p = malloc(); //obj0
        // if (...) {
        //   free(p); //F
        //   p = malloc(); //obj1
        // }
        // *p; //U
        // From the (path-insensitive) static analysis' view, U can access either
        // obj0 or obj1, so U/F can use the same object, but this is a FP..
        // (2) Check whether F site and pto propagation for U site are compatiable
        // within one thread.
        // -- e.g.,
        // p = malloc(); //obj
        // if (...) {
        //   free(p); //F
        // } else {
        //    g = p;
        // }
        // *g; //U
        // This case is simpler than above, there are no alternative pto records
        // for the U site (we have disabled the path-cov test), however, we still
        // need to verify that the F site, U site, and pto propagation of U must
        // be compatiable in a single thread (not for this example, so a FP).
        // (3) Model the heap allocation.
        // -- e.g.,
        //  while (true) {
        //    p = malloc();
        //    if (...) break;
        //    free(p); //F
        //  }
        //  *p; //U
        // Our single entry analysis concludes that U/F share the same obj w/o
        // modelling the multi-times heap allocation, however, U always uses
        // a different fresh heap allocation happening after F, thus a FP.
        bool _validateSeqUAF(InstLoc *floc, AliasObject *fobj, InstLoc *uloc, AliasObject *uobj) {
            if (!uobj || !floc || !uloc) {
                //To be conservative, return true by default.
                return true;
            }
            std::set<PointerPointsTo*> uptos;
            uobj->getUsePtos(uloc, uptos);
            if (uptos.empty()) {
                //This seems impossible..
                dbgs() << "!!! _validateSeqUAF(): cannot get any "
                << "uptos for obj " << (const void*)uobj << " @ ";
                uloc->print_light(dbgs(),true); 
                return true;
            }
            //First, we need to verify that F, U, and U's pto propagation
            //can happen within the same thread.
            Thread tr;
            PointerPointsTo *upto = nullptr;
            for (PointerPointsTo *pto : uptos) {
                if (!pto) {
                    continue;
                }
                if (pto->propagatingHistory.empty() || 
                    tr.init(pto->propagatingHistory) < 0)
                {
                    //Seems impossible..
                    dbgs() << "!!! _validateSeqUAF(): null or ininvalid pto propagartion, pto: ";
                    pto->print(dbgs());
                    dbgs() << "propagation: ";
                    pto->printProp(dbgs(), true, true);
                    continue;
                }
                //"tr" now contains all the U pto propagation history,
                //now test whether F can fit in (but w/o actual insertion).
                if (!tr.testInsertLoc(floc)) {
                    //F cannot happen in the same thread given the U
                    //pto propagation.
                    return false;
                }
                //BTW model the heap allocation here, basically ensure that if
                //"uobj" is a heap obj, its allocation site will not be reachable
                //from the F site.
                InstLoc *aloc = nullptr;
                if (uobj->isHeapLocationE(&aloc)) {
                    if (!aloc) {
                        aloc = pto->propagatingHistory[0];
                    }
                    //Ensure that the origination is an allocation call.
                    if (aloc && dyn_cast<CallBase>(aloc->inst)) {
                        //If F must first reach A then U, then the freed and used must
                        //be different heap allocation instances.
                        if (!_canRefSameHeapObj(aloc, floc, uloc, 1)) {
                            return false;
                        }
                    } else {
                        dbgs() << "!!! _validateSeqUAF(): no allocation site identified for uobj.\n";
                    }
                }
                //Ok, F is compatiable with U pto propagation.
                //TODO: what if there are multiple U ptos?
                upto = pto;
                break;
            }
            if (!upto) {
                //Possibly because no upto has a valid propagation history,
                //TODO: why? This is less likely..
                dbgs() << "!!! _validateSeqUAF(): cannot get a valid upto!\n";
                return true;
            }
            //Now consider whether the U pto can be overwritten
            //by alternations if we put F in the thread.
            //First get all other possible U ptos
            Value *up = upto->targetPointer;
            std::set<PointerPointsTo*> *a_uptos = this->getPointsToObjects(
                                                             uloc->ctx, up);
            if (!a_uptos) {
                //should be impossible..
                return true;
            }
            //Collect alternative pto propagation locations, following below rules:
            //(1) the pto points to different obj than "upto";
            //(2) the propagation location doesn't necessarily appear in upto's
            //propagation path.
            std::set<InstLoc*> alt_locs;
            for (PointerPointsTo *pto : *a_uptos) {
                if (!pto || uptos.find(pto) != uptos.end() || 
                    pto->targetObject == upto->targetObject ||
                    pto->targetObject == uobj)
                {
                    continue;
                }
                for (InstLoc *loc : pto->propagatingHistory) {
                    if (!loc || std::find(upto->propagatingHistory.begin(),
                                          upto->propagatingHistory.end(), loc) != upto->propagatingHistory.end()) {
                        continue;
                    }
                    if (!tr.testInsertLoc(loc,InstLocTr::TY_DEF,true,true)) {
                        alt_locs.insert(loc);
                    }
                }
            }
            //Now we will add F loc into the thread, then if we find all the
            //paths to/from F within the thread will be blocked by the
            //"alt_locs", that means as long as F is involved, the upto
            //propagation will be infeasible, making this a FP warning.
            std::shared_ptr<InstLocTr> fLocTr = tr.insertLoc(floc);
            if (!fLocTr) {
                //Should be impossible since we have tested this before.
                return false;
            }
            if (!tr.reachableWithBlockers(fLocTr,alt_locs)) {
                return false;
            }
            /*
            //If there is a pto pointing to a different object than "obj",
            //and F site is ineviatbly on its propagating path, we will conclude
            //that this seq UAF with "obj" is invalid.
            for (PointerPointsTo *pto : *a_uptos) {
                if (!pto || uptos.find(pto) != uptos.end() || 
                    pto->targetObject == uobj) {
                    continue;
                }
                if (pto->propagatingHistory.empty()) {
                    continue;
                }
                Thread tr;
                if (tr.init(pto->propagatingHistory) < 0) {
                    continue;
                }
                //Test whether F site is ineviatable in this propagating path.
                if (tr.insertLoc(floc,InstLocTr::TY_DEF,true,true)) {
                    return false;
                }
            }
            */
            return true;
        }

        //Return true if "loc" is within a pthread entry function.
        bool inPTEntry(InstLoc *loc) {
            if (!loc || this->callbacks.find(2) == this->callbacks.end()) {
                return false;
            }
            return (this->callbacks[2].find(loc->getEntryFunc()) != this->callbacks[2].end());
        }

        //Try to validate and fire an UAF warning.
        //From the perspective of instruction sequences, we have two basic types of UAFs:
        //(1) free'd (concrete obj0) -> (escape->fetch)* -> used (an equivalent dummy obj1 to obj0)
        //(2) obj0 (escape->fetch)* -> free'd (dummy obj1 equivalent to obj0) -> obj0 (escape->fetch)* -> used (dummy obj2 equivalent to obj0)
        //NOTE: "*" contains the case where there is no (escape->fetch) (e.g., a first-order UAF).
        //Params:
        //"floc": the free site; "uloc": the use site
        //"ep0": this will be nullptr in type (1) UAF, while in type (2) it records the info of the eqv obj pair of obj0 and the freed obj1.
        //"ep1": for type (1) it records the pair info of (freed) obj0 and (used) obj1, while for type (2) obj0 and (used) obj2. 
        int fireAnUAF(EqvObjPair *ep0, InstLoc *floc, EqvObjPair *ep1, InstLoc *uloc) {
            static std::map<InstLoc*, std::set<InstLoc*>> fired, bounced;
            //"ep1" cannot be null in all the cases, as well as "floc" and "uloc".
            if (!ep1 || !floc || !uloc) {
                return 0;
            }
            if (fired.find(floc) != fired.end() && 
                fired[floc].find(uloc) != fired[floc].end()) {
                //A warning has already been issued for this pair of u/f InstLocs.
                return 0;
            }
            //NOTE: currently our hendling of pthread entry functions is context-insensitive -
            //we cannot differentiate them based on the pthread creation sites. In other words,
            //a same "floc" or "uloc" within a pthread entry can actually relate to different
            //pthread creation sites, resulting in very different results of FP filtering.
            //So for safety, we disable the InstLoc based "bounce" mechanism for locs within
            //pthread entries.
            //TODO: we should consider to support the creation site as a context in InstLoc.
            if (!this->inPTEntry(floc) && !this->inPTEntry(uloc)) {
                if (bounced.find(floc) != bounced.end() &&
                    bounced[floc].find(uloc) != bounced[floc].end()) {
                    // A warning has already been filtered out for this pair of u/f InstLocs.
                    return 0;
                }
            }
            //FP filtering.
            if (validateUAF(ep0, floc, ep1, uloc)) {
                //Update the cache.
                fired[floc].insert(uloc);
                bool is_f2u = uloc->reachable(floc);
                std::string hint = (is_f2u ? "Flow: Seq" : "Flow: Con");
                printUAFWarningInJson(dbgs(), ep0, floc, ep1, uloc, hint);
                return 1;
            }
            bounced[floc].insert(uloc);
            return 0;
        }

        //Return 0 if passing the verification, otherwise specific negative error code.
        int _validateUAF_heu(InstLoc *floc, AliasObject *fobj,
                             InstLoc *uloc, AliasObject *uobj)
        {
            //Filter (stack obj): it seems less likely that a stack obj can be freed
            //in the well-written kernel code.
            if ((fobj && fobj->isFunctionLocalE()) ||
                (uobj && uobj->isFunctionLocalE()))
            {
#ifdef DEBUG_FP_FILTERING
                dbgs() << "_validateUAF_heu(): the U/F obj is stack based.\n";
#endif
                return -1;
            }
            //Filter (refcnt): Give up the cases where ref count mechanism is
            //enabled, since now we are unable to carefully reason about the refcnt.
            if (_isWithRefcnt(floc, uloc)) {
#ifdef DEBUG_FP_FILTERING
                dbgs() << "_validateUAF_heu(): reference count protection detected.\n";
#endif
                return -2;
            }
            //Filter (recursive structure): currently we lack the capability
            //to precisely reason about the recursive structure related operations
            //(e.g., linked list insertion removal) and differentiate the nodes
            //of these structures, so we opt to exclude the UAF warnings with U/F
            //objs to be a recursive structure node.
            if (fobj && !fobj->isGlobalObjectE() && _isFromLinkedList(floc, fobj, true)) {
#ifdef DEBUG_FP_FILTERING
                dbgs() << "_validateUAF_heu(): the F obj is a recursive st node.\n";
#endif
                return -3;
            }
            if (uobj && !uobj->isGlobalObjectE() && _isFromLinkedList(uloc, uobj, false)) {
#ifdef DEBUG_FP_FILTERING
                dbgs() << "_validateUAF_heu(): the U obj is a recursive st node.\n";
#endif
                return -3;
            }
            //Filter (obj-bound indirect calls): there are often cases where the
            //calling contexts of F/U both involve an indirect call like
            //"obj->f(obj,...)" (e.g., a func ptr is retrieved from an obj and the
            //obj itself is passed as an arg), kind of simulating C++ member functions
            //w/ C. However, such cases often lead to different bounded objs to be
            //accessed in U/F sites, resulting in FPs. Before we have a better solution
            //to reason about the bounded objs, we detect such cases and exclude them.
            if (_hasUnrelObjBoundIndirectCalls(floc, uloc)) {
#ifdef DEBUG_FP_FILTERING
                dbgs() << "_validateUAF_heu(): obj-bound indirect call detected.\n";
#endif
                return -4;
            }
            //Filter: if "fobj" is a heap obj, but "floc" is post-dominated by the
            //heap allocation site, this strongly indicates that F/U will not access
            //the same heap allocation.
            //e.g.,
            // while(true) {
            //    p = malloc() //allocation site
            //    if (...) break;
            //    free(p); //F site
            // }
            // *P; //U site
            InstLoc *aloc = nullptr;
            if (fobj && fobj->isHeapLocationE(&aloc) && floc) {
                if (aloc && aloc->postDom(floc)) {
#ifdef DEBUG_FP_FILTERING
                    dbgs() << "_validateUAF_heu(): free of a heap obj is post-dominated"
                    << " by its allocation.\n";
#endif
                    return -5;
                }
            }
            return 0;
        }

        //Return "true" if the F site must lead to a invalid return value
        //(i.e., nullptr or ERR_PTR), the ret inst will be put in "rets".
        bool _isFreeWithInvalidRet(InstLoc *floc, std::set<InstLoc*> &rets) {
            rets.clear();
            if (!floc || !floc->hasCtx()) {
                return false;
            }
            //Only proceed when the host function of F returns a ptr.
            Function *hf = floc->getFunc();
            if (!hf) {
                return false;
            }
            Type *rty = hf->getReturnType();
            if (!rty || !rty->isPointerTy()) {
                return false;
            }
            //Ok, now get all killer locs that lead to invalid ptrs returned.
            //Since it's "killer" loc, we provide an expr modelling a valid
            //ptr which will be "killed".
            expr v = get_z3v();
            expr echk = (v != 0 && v <= z3c.bv_val(-4096, 64));
            std::set<InstLoc*> klocs;
            _getKillerRets(floc->ctx, echk, klocs);
            if (klocs.empty()) {
                return false;
            }
            //See whether the F site will ineviatbly return with these killers.
            std::set<BasicBlock*> rbbs;
            BBTraversalHelper::getRetBBs(hf, rbbs);
            if (rbbs.empty()) {
                return false;
            }
            for (BasicBlock *rb : rbbs) {
                if (!rb || !rb->getFirstNonPHIOrDbg()) {
                    continue;
                }
                InstLoc *rloc = InstLoc::getLoc(rb->getFirstNonPHIOrDbg(),floc->ctx,true);
                if (!rloc || !rloc->reachable(floc)) {
                    continue;
                }
                if (rloc->reachable(floc,&klocs)) {
                    return false;
                }
                rets.insert(rloc);
            }
            return true;
        }

        //Return true if F is in a callee, while U happens after the callee returns.
        //NOTE: we assume that this is a seq UAF case!!
        bool _isUAFRet(CallContext *fctx, CallContext *uctx) {
            if (!fctx || fctx->empty() || !uctx || uctx->empty()) {
                return false;
            }
            //Get the length of the common prefix..
            unsigned i = 0;
            for (; i < std::min(fctx->callSites->size(), uctx->callSites->size()); ++i) {
                if (fctx->callSites->at(i) != uctx->callSites->at(i)) {
                    break;
                }
            }
            return (i < fctx->callSites->size());
        }

        //Return 0 if passing the verification, other wise specific negative error code.
        int _validateUAF_obj(InstLoc *floc, AliasObject *fobj,
                             InstLoc *uloc, AliasObject *uobj)
        {
            if (!floc || !uloc) {
                return 0;
            }
            //Indicate whether the free site reach the use site in the CFG
            //(within a single entry invocation).
            bool is_f2u = uloc->reachable(floc);
            //Try to partially support path-sensitivity (e.g., regarding the invalid
            //return value associated with the "free").
            std::set<InstLoc*> krets;
            bool is_kret = _isFreeWithInvalidRet(floc, krets);
            //In theory, if F/U are in different entry invocations but both
            //use the same allocated *heap* obj according to our summary,
            //this case should be a FP, because the heap allocation is per-entry,
            //so two invocations must have different heap objs - in our summary
            //they are the same becuase of our modelling of the allocation
            //site (it only results in one fixed obj and we only analyze each
            //entry once). It's possiblt that, e.g., the F obj is leaked to
            //some shared ptr and then accessed by U via that ptr, but in
            //this case we should have a different warning involving the
            //E/F between the heap obj and a dummy obj, instead of two identical
            //heap objs.
            //So it sounds like we can simply exclude all con cases with
            //2 identical heap objs? Unfortunately not for now because
            //we are not confident that we can catch all the heap obj
            //escape-and-retrieve-again cases, since we may not properly
            //create all the required dummy objects to match the heap objs:
            //(1) we have disabled the dummy pto creation based on path
            //coverage test (since there can be two many ifeasible paths
            //leading to too many unnecessary dummy pto creation).
            //(2) we haven't implemented the dummy pto creation when considering
            //the concurrent situation (global mem may be overwritten at any
            //time by code other than current entry invocation).
            //So, what we opt to do now is that we need to carefully reason
            //about all these identical heap obj warnings to decide whether
            //it's possible to make an escape-and-retrieve case, if not,
            //it will be a FP.
            if (!is_f2u) {
                //Filter: if we know that:
                //(1) F always uses a ptr that is obtained purely in a local
                //way (e.g., not loaded from any shared mem) pointing to a
                //heap obj, we know for sure that what is freed must be
                //exactly that heap allocation (e.g., other entry invocation
                //cannot tamper with the local obtained ptr via either "path
                //cov test" or "con execution"), and
                //(2) so does U.
                //We can conclude that U/F cannot access the same heap obj
                //in their different entry invocations.
                bool is_fheap = (fobj && fobj->isHeapLocationE());
                bool is_flocal = (is_fheap && _isFreeFromLocalPtr(floc,fobj));
                bool is_uheap = (uobj && uobj->isHeapLocationE());
                bool is_ulocal = (is_uheap && _isUseFromLocalPtr(uloc,uobj));
                if (is_flocal && is_ulocal) {
#ifdef DEBUG_FP_FILTERING
                    dbgs() << "_validateUAF_obj(): U/F both have local ptr to"
                    << " heap objs (con).\n";
#endif
                    return -1;
                }
                //Filter: if we know that:
                //(1) F has local ptr to heap as aforementioned.
                //(2) the freed heap obj will not be address taken to any
                //shared mem within the same thread of F (or before the
                //invalid ptr is returned).
                //Then U will be unable to access the same freed heap obj.
                if (is_flocal) {
                    //Does the freed heap obj escape?
                    std::vector<AliasObject*> his;
                    his.push_back(fobj);
                    Thread tr;
                    tr.insertLoc(floc);
                    int dir = 0;
                    if (is_kret && !krets.empty()) {
                        tr.insertLoc(*krets.begin());
                        dir = -1;
                    }
                    //Escape before/after the free sites both work.
                    if (!_hasGlobalEscape(his,floc,&tr,dir)) {
                        //Safe
#ifdef DEBUG_FP_FILTERING
                        dbgs() << "_validateUAF_obj(): F has local ptr to a heap obj,"
                               << " which doesn't escape within the invocation (con).\n";
#endif
                        return -2;
                    }
                }
                //Filter: similar to above, but this time for the U site.
                if (is_ulocal) {
                    //Does the used heap obj escape?
                    std::vector<AliasObject*> his;
                    his.push_back(uobj);
                    Thread tr;
                    tr.insertLoc(uloc);
                    //Must escape before the U site to make UAF possible.
                    if (!_hasGlobalEscape(his,uloc,&tr,-1)) {
                        //Safe
#ifdef DEBUG_FP_FILTERING
                        dbgs() << "_validateUAF_obj(): U has local ptr to a heap obj,"
                               << " which doesn't escape before U within the invocation (con).\n";
#endif
                        return -3;
                    }
                }
            }
            //Filter (Seq UAF data flow check): if F reaches U and both access the
            //same object, we will have no EF paths, so we need some extra checks
            //regarding data flows.
            if (is_f2u) {
                if (is_kret && _isUAFRet(floc->ctx, uloc->ctx)) {
#ifdef DEBUG_FP_FILTERING
                    dbgs() << "_validateUAF_obj(): F is with nullptr returned, then U (seq).\n";
#endif
                    return -4;
                }
                if (!_validateSeqUAF(floc, fobj, uloc, uobj)) {
#ifdef DEBUG_FP_FILTERING
                    dbgs() << "_validateUAF_obj(): infeasible data flow from F to U (seq).\n";
#endif
                    return -5;
                }
            }
            return 0;
        }

        //Decide whether this UAF is feasible, by encoding control/data flow constraints into
        //a partial-order constraint system that will then be solved with z3.
        bool validateUAF(EqvObjPair *ep0, InstLoc *floc, EqvObjPair *ep1, InstLoc *uloc) {
            if (!ep1 || !floc || !uloc) {
                return false;
            }
            //Get the freed and used objects.
            AliasObject *fobj = (ep0 ? ep0->dst : ep1->src);
            AliasObject *uobj = ep1->dst;
            if (!fobj || !uobj) { 
                return false;
            }
#ifdef DEBUG_FP_FILTERING
            dbgs() << "validateUAF(): about to validate the UAF warning, loc0: ";
            floc->print_light(dbgs(), false);
            dbgs() << ", loc1: ";
            uloc->print_light(dbgs(), false);
            dbgs() << ", fobj: " << (const void*)fobj
            << ", uobj: " << (const void*)uobj << "\n";
#endif
            //First perform a set of heuristic based FP filtering (e.g., recursive
            //structure recognization).
            //TODO: we need to progressively improve our tool's analysis capability
            //to avoid these heuristics in the future.
            if (_validateUAF_heu(floc, fobj, uloc, uobj) < 0) {
#ifdef DEBUG_FP_FILTERING
                dbgs() << "validateUAF(): _validateUAF_heu() fail.\n";
#endif
                return false;
            }
            //Then the data flow check between U/F sites (e.g., whether they can
            //really access the same object).
            //TODO: we need a better modelling of the memory allocation for our
            //analysis, also we need to make the data flow check more systematic
            //(e.g., also union it with the E/F path check).
            if (_validateUAF_obj(floc, fobj, uloc, uobj) < 0) {
#ifdef DEBUG_FP_FILTERING
                dbgs() << "validateUAF(): _validateUAF_obj() fail.\n";
#endif
                return false;
            }
            //Now it's the time to do the multi-factor FP filtering, based on
            //systematic partial-order constraints construction and sloving.
            ThreadSched trs(this);
#ifdef DEBUG_FP_FILTERING
            auto t_st = std::chrono::system_clock::now();
#endif
            //(0) First decide the control-flow to trigger the UAF (e.g., how many and which threads?),
            //based on this skeleton, we can recognize other corresponding key stmts. later.
            //This control flow skeleton is framed by the U/F stmt. and the object fetch/escape path.
            if (trs.initUAFThreads(floc, fobj, InstLocTr::TY_FREE,
                                   uloc, uobj, InstLocTr::TY_USE) < 0)
            {
                //Init fail.
#ifdef DEBUG_FP_FILTERING
                dbgs() << "validateUAF(): initUAFThreads() fail.\n";
#endif
                return false;
            }
            //dbgs() << "after initUAFThreads():\n";
            //Put in the escape/fetch path related nodes.
            if (trs.addEFPaths(ep0, ep1) < 0) {
#ifdef DEBUG_FP_FILTERING
                dbgs() << "validateUAF(): addEFPathToThreads() fail.\n";
#endif
                return false;
            }
#ifdef DEBUG_FP_FILTERING
            std::chrono::duration<double> e_sec = std::chrono::system_clock::now() - t_st;
            dbgs() << "validateUAF(): after addEFPathToThreads(), time spent (s): "
            << e_sec.count() << "\n";
            t_st = std::chrono::system_clock::now();
#endif
            //dbgs() << "after addEFPathToThreads():\n";
            //(1) Identify the remaining key statements related to this potential UAF, and enforce
            //the related partial-order constraints.
            //(1)-1 global variable set/check along the paths to F/U stmt. (guarding not
            //only F/U, but also other nodes like escape/fetch).
            //(1)-2 lock/unlock stmt. along the path, similar to (1)-2
            if (trs.addSuppTrLocs() < 0) {
                // "addSuppTrLocs()" has made an early decision that the bug is infeasible.
#ifdef DEBUG_FP_FILTERING
                dbgs() << "validateUAF(): addSuppTrLocs() decides that the bug is infeasible!\n";
#endif
                return false;
            }
#ifdef DEBUG_FP_FILTERING
            e_sec = std::chrono::system_clock::now() - t_st;
            dbgs() << "validateUAF(): after addSuppTrLocs(), time spent (s): "
            << e_sec.count() << "\n";
            t_st = std::chrono::system_clock::now();
#endif
            //(2) thread-level sync stmt. like fork()/join() (happens-before analysis)
            if (trs.addSyncTrLocs() < 0) {
                //A placeholder early rejection mechanism, but not effective yet...
#ifdef DEBUG_FP_FILTERING
                dbgs() << "validateUAF(): addSyncTrLocs() decides that the bug is infeasible!\n";
#endif
                return false;
            }
            //(3) Enforce the natural intra-thread partial-order constraints.
            trs.addSeqConstraint2All();
#ifdef DEBUG_FP_FILTERING
            dbgs() << "validateUAF(): going to solve partial-order constraints for"
            << " the thread sched:\n";
            trs.print(dbgs());
#endif
            //(4) Solve the partial-order constraint system.
            std::vector<void*> seq;
            bool v_res = trs.validateAll(&seq);
#ifdef DEBUG_FP_FILTERING
            e_sec = std::chrono::system_clock::now() - t_st;
            dbgs() << "validateUAF(): after validateAll(), result: " << v_res
            << ", time spent (s): "
            << e_sec.count() << "\n";
#endif
            //TODO: show the possible sequence ("seq") to trigger the UAF, if feasible.
            return v_res;
        }

        //The arguments are the same as "fireAnUAF()".
        //Try to print the detailed UAF warning in Json format.
        void printUAFWarningInJson(llvm::raw_ostream &O, EqvObjPair *ep0, InstLoc *floc,
                                   EqvObjPair *ep1, InstLoc *uloc, const std::string &hint) {
            if (!ep1 || !floc || !uloc) {
                return;
            }
            O << "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n";
            O << "\"warn_data\":{";
            O << "\"by\":\"UAFDetector\",";
            O << "\"hint\":\"" << hint << "\",";
            O << "\"loc0\":{";
            printInstlocJson(floc,O);
            O << "}";
            O << ",\"loc1\":{";
            printInstlocJson(uloc,O);
            O << "}";
            if (ep0) {
                O << ",\"ep0\":";
                ep0->printInJson(O);
            }
            //"ep1" must not be null.
            O << ",\"ep1\":";
            ep1->printInJson(O);
            O << "}\n";
            O << "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n";
        }
    };

}

#endif //PROJECT_MODULESTATE_H
