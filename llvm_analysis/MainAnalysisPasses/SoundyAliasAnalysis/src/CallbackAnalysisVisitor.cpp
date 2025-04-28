#include "CallbackAnalysisVisitor.h"

using namespace llvm;

namespace DRCHECKER {

void _freePtoSet(std::set<PointerPointsTo*> *ptos) {
    if (!ptos) {
        return;
    }
    for (auto p : *ptos) {
        delete p;
    }
    delete ptos;
    return;
}

//The goal is to capture the function pointer assignment to special structs like
//"work_struct", which indicates a bottom-half callback.
void CallbackAnalysisVisitor::visitStoreInst(StoreInst &I) {
    Value *v = I.getValueOperand();
    Value *p = I.getPointerOperand();
    if (!v || !p) {
        return;
    }
    //We only care about the store of function pointers.
    Type *vty = v->getType();
    if (!vty || !vty->isPointerTy() ||
        !dyn_cast<FunctionType>(vty->getPointerElementType())) {
            return;
    }
    //Then verify that the function prototype matches the known
    //bottom-half callbacks, currently we have two in mind:
    //(1) workqueue callbacks:  void (*work_func_t)(struct work_struct *work)
    //(2) tasklet callbacks: void (*callback)(struct tasklet_struct *t)
    FunctionType *fty = dyn_cast<FunctionType>(vty->getPointerElementType());
    // Both prototypes above have only one argument.
    if (!fty || fty->getNumParams() != 1) {
        return;
    }
    // The parameter is either a work_struct* or a tasklet_struct*.
    Type *pty = fty->getParamType(0);
    if (!pty || !pty->isPointerTy()) {
        return;
    }
    StructType *sty = dyn_cast<StructType>(pty->getPointerElementType());
    if (!sty) {
        return;
    }
    std::string stn = sty->getName().str();
    CallBackInfo cbi;
    int f_cls = 0;
    if (stn == "struct.work_struct" ||
        stn.find("struct.work_struct.") == 0) {
        // bottom-half: workqueue
        // extract the work_struct used as the arg and record it.
        // Note that the store target should be the func ptr field within
        // the "work_struct", while the callback arg should be the pointer
        // to the "work_struct".
        std::set<PointerPointsTo*> *ptos = PointsToUtils::getPointsToObjects(this->currState,
                                                                             this->ctx, p);
        std::set<PointerPointsTo*> *nptos = this->adjPto2Base(ptos, "struct.work_struct");
        if (nptos && !nptos->empty()) {
            cbi.addArgPto(0, nptos);
            f_cls = 0;
        } else {
            if (nptos)
                delete nptos;
            return;
        }
    } else if (stn == "struct.tasklet_struct" ||
               stn.find("struct.tasklet_struct.") == 0) {
        // bottom-half: tasklet
        // extract the tasklet_struct used as the arg and record it.
        // Note that the store target should be the func ptr field within
        // the "tasklet_struct", while the callback arg should be the pointer
        // to the "tasklet_struct".
        std::set<PointerPointsTo*> *ptos = PointsToUtils::getPointsToObjects(this->currState,
                                                                             this->ctx, p);
        std::set<PointerPointsTo*> *nptos = this->adjPto2Base(ptos, "struct.tasklet_struct");
        if (nptos && !nptos->empty()) {
            cbi.addArgPto(0, nptos);
            f_cls = 1;
        } else {
            if (nptos)
                delete nptos;
            return;
        }
    } else {
        return;
    }
    //Get the function body.
    std::set<Function*> funcs;
    this->getFuncsFromValue(v,funcs);
    if (!funcs.empty()) {
        //Record the collected callback info to the global database.
        this->add2GlobalRecords(&funcs, f_cls, nullptr, &cbi, &I);
    } else {
        //Free the pto sets.
        for (auto e : cbi.arg_ptos) {
            for (PointerPointsTo *p : e.second) {
                if (p) delete p;
            }
        }
    }
    return;
}

VisitorCallback *CallbackAnalysisVisitor::visitCallInst(CallInst &I, Function *targetFunction,
                                                        CallContext *oldCtx,
                                                        CallContext *currCtx) {
    // Skip if this is a kernel internal function w/o a function body.
    if (targetFunction->isDeclaration()) {
        //Take care of some kernel callback registration functions.
        std::string fn = targetFunction->getName().str();
        if (fn == "tasklet_setup") {
            //void @tasklet_setup(%struct.tasklet_struct*, void (%struct.tasklet_struct*)*)
            Value *pst = I.getArgOperand(0);
            std::set<PointerPointsTo*> *ptos = PointsToUtils::getPointsToObjects(this->currState,
                                                                                 this->ctx, pst);
            std::set<PointerPointsTo*> *nptos = this->adjPto2Base(ptos, "struct.tasklet_struct");
            if (nptos && !nptos->empty()) {
                Value *pf = I.getArgOperand(1);
                std::set<Function*> funcs;
                this->getFuncsFromValue(pf, funcs);
                if (!funcs.empty()) {
                    // Record the collected callback info to the global database.
                    CallBackInfo cbi;
                    cbi.addArgPto(0, nptos);
                    this->add2GlobalRecords(&funcs, 1, nullptr, &cbi, &I);
                } else {
                    _freePtoSet(nptos);
                }
            }
        } else if (fn == "pthread_create") {
            //i32 @pthread_create(i64* noundef, %union.pthread_attr_t* noundef, i8* (i8*)* noundef, i8* noundef)
            //int pthread_create(pthread_t *restrict thread, const pthread_attr_t *restrict attr,
            //void *(*start_routine)(void *), void *restrict arg);
            Value *pf = I.getArgOperand(2);
            std::set<Function*> funcs;
            this->getFuncsFromValue(pf, funcs);
            if (!funcs.empty()) {
                CallBackInfo cbi;
                // Get the arg ptos.
                Value *pa = I.getArgOperand(3);
                std::set<PointerPointsTo *> *ptos = PointsToUtils::getPointsToObjects(
                                                    this->currState, this->ctx, pa);
                //The arg 3 of pthread_create() will be the sole arg of the pthread entry func.
                cbi.addArgPto(0, ptos, true);
                // Record the pto for storing the thread id.
                Value *pth = I.getArgOperand(0);
                std::set<PointerPointsTo *> *tptos = PointsToUtils::getPointsToObjects(
                                                     this->currState, this->ctx, pth);
                cbi.addPc2Tid(InstLoc::getLoc(&I,this->ctx,true), tptos);
                this->add2GlobalRecords(&funcs, 2, nullptr, &cbi, &I);
            }
        } else if (fn == "pthread_join") {
            //i32 @pthread_join(i64 noundef, i8** noundef)
            //int pthread_join(pthread_t thread, void **retval);
            //The goal here is to find the corresponding creation site of the thread
            //(pthread_create()) that pthread_join() is waiting for.
            Value *tid = I.getArgOperand(0);
            InstLoc *loc = InstLoc::getLoc(tid,this->ctx,true);
            //Trace back inter-procedurally to the mem location the tid is loaded from.
            std::set<InstLoc*> loads;
            getSrcLoad(loc, loads);
            std::set<PointerPointsTo*> tptos;
            for (InstLoc *lloc : loads) {
                if (!lloc || !dyn_cast<LoadInst>(lloc->inst)) {
                    continue;
                }
                LoadInst *li = dyn_cast<LoadInst>(lloc->inst);
                Value *p = li->getPointerOperand();
                std::set<PointerPointsTo *> *tpto = PointsToUtils::getPointsToObjects(
                                                    this->currState, lloc->ctx, p);
                if (tpto && !tpto->empty()) {
                    for (PointerPointsTo *pt : *tpto) {
                        if (pt) tptos.insert(pt);
                    }
                }
            }
            //Now "tptos" hold all pto records to the mem locs that the thread id is
            //retrieved from, next we need to compare them with the mem locs used
            //in the previous pthread_create() call sites, if same, then we get a
            //pair of pthread_create() and pthread_join().
            if (!tptos.empty() &&
                this->currState.callbacks.find(2) != this->currState.callbacks.end())
            {
                InstLoc *jloc = InstLoc::getLoc(&I,this->ctx,true);
                auto &pcmap = this->currState.callbacks[2];
                for (auto &e : pcmap) {
                    if (!e.first || !e.second) {
                        continue;
                    }
                    e.second->matchPcSites(jloc, tptos);
                }
            }
        }
        //TODO: we may need to handle other pthread functions like pthread_cancel(),
        //pthread_cond_broadcast(), etc.
        return nullptr;
    }
    // create a new ModAnalysisVisitor
    CallbackAnalysisVisitor *vis = new CallbackAnalysisVisitor(currState, targetFunction, currCtx);
    return vis;
}

std::set<PointerPointsTo*> *CallbackAnalysisVisitor::adjPto2Base(std::set<PointerPointsTo*> *ptos,
                                                                 std::string stn) {
    if (!ptos || ptos->empty()) {
        return nullptr;
    }
    std::set<PointerPointsTo*> *res = new std::set<PointerPointsTo*>();
    for (PointerPointsTo *pto : *ptos) {
        if (!pto) {
            continue;
        }
        AliasObject *obj = pto->targetObject;
        while (obj) {
            StructType *stTy = dyn_cast<StructType>(obj->targetType);
            if (stTy) {
                std::string cstn = stTy->getName().str();
                if (cstn.find(stn) == 0) {
                    //Got it, we now need to generate a new pto record pointing
                    //to the base of this obj.
                    PointerPointsTo *npto = new PointerPointsTo(nullptr, obj, 0);
                    res->insert(npto);
                }
            }
            obj = obj->parent;
        }
    }
    if (res->empty()) {
        delete res;
        return nullptr;
    }
    return res;
}

//Trace back a value to get all functions it represents (e.g., "phi" may merge multiple
//functions to a single llvm value).
void CallbackAnalysisVisitor::getFuncsFromValue(Value *v, std::set<Function*> &res) {
    if (!v) {
        return;
    }
    if (dyn_cast<Function>(v)) {
        res.insert(dyn_cast<Function>(v));
        return;
    }
    // Try strpping the pointer casts.
    Value *nv = v->stripPointerCastsForAliasAnalysis();
    if (!nv) {
        return;
    }
    if (dyn_cast<Function>(nv)) {
        res.insert(dyn_cast<Function>(nv));
    } else if (dyn_cast<SelectInst>(nv)) {
        SelectInst *si = dyn_cast<SelectInst>(nv);
        this->getFuncsFromValue(si->getTrueValue(), res);
        this->getFuncsFromValue(si->getFalseValue(), res);
    } else if (dyn_cast<PHINode>(nv)) {
        PHINode *phi = dyn_cast<PHINode>(nv);
        for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
            Value *iv = phi->getIncomingValue(i);
            this->getFuncsFromValue(iv, res);
        }
    }
    return;
}

//If "key" is nullptr, we will by default use InstLoc of "refInst" as the key.
void CallbackAnalysisVisitor::add2GlobalRecords(std::set<Function*> *funcs, int f_cls,
                                void *key, CallBackInfo *cbi, Instruction *refInst)
{
    if (!funcs || funcs->empty() || !cbi) {
        return;
    }
    std::string fns;
    InstLoc *refloc = InstLoc::getLoc(refInst,this->ctx,true);
    for (Function *f : *funcs) {
        if (!f) {
            continue;
        }
        fns += (f->getName().str() + ", ");
        CallBackDir *cbd = nullptr;
        if (this->currState.callbacks.find(f_cls) == this->currState.callbacks.end() ||
            this->currState.callbacks[f_cls].find(f) == this->currState.callbacks[f_cls].end() ||
            !this->currState.callbacks[f_cls][f])
        {
            cbd = new CallBackDir();
            this->currState.callbacks[f_cls][f] = cbd;
        } else {
            cbd = this->currState.callbacks[f_cls][f];
        }
        cbd->addCB((key ? key : (void*)refloc), cbi);
    }
    //Print out the registration locations of these callbacks for future reference.
    if (refloc) {
        dbgs() << "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n";
        dbgs() << "{\"funcs\":\"" << fns << "\",\"ref\":{";
        printInstlocJson(refloc,dbgs());
        dbgs() << "}}\n";
        dbgs() << "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n";
    }
    return;
}

} // namespace DRCHECKER