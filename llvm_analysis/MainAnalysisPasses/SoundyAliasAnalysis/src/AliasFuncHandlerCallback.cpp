//
// Created by machiry on 12/4/16.
//

#include "AliasFuncHandlerCallback.h"
#include "AliasObject.h"

using namespace llvm;

namespace DRCHECKER {

#define DEBUG_CREATE_HEAP_OBJ

    void* AliasFuncHandlerCallback::handleAllocationFunction(InstLoc *callInstLoc,
                                    Function *targetFunction, void *private_data) {
        // Just create a new object
        return createNewHeapObject(callInstLoc, targetFunction, private_data);
    }

    void* AliasFuncHandlerCallback::handleCustomFunction(InstLoc *callInstLoc,
                                    Function *targetFunction, void *private_data) {
        // Create a new heap object
        return createNewHeapObject(callInstLoc, targetFunction, private_data);
    }

    void AliasFuncHandlerCallback::setPrivateData(void *data) {
        this->currState = (GlobalState*)data;
    }

    void* AliasFuncHandlerCallback::createNewHeapObject(InstLoc *callInstLoc,
                                        Function *targetFunction, void *private_data) {
        if (!callInstLoc || !dyn_cast<CallInst>(callInstLoc->inst)) {
            dbgs() << "AliasFuncHandlerCallback::createNewHeapObject(): Invalid call inst!\n";
        }
        if (!targetFunction) {
#ifdef DEBUG_CREATE_HEAP_OBJ
            dbgs() << "AliasFuncHandlerCallback::createNewHeapObject(): null targetFunction!!\n";
#endif
            return nullptr;
        }
        CallInst *callInst = dyn_cast<CallInst>(callInstLoc->inst);
        Value *targetSize = nullptr;
        // if the call is to kmalloc, get the size argument.
        if (this->targetChecker->is_kmalloc_function(targetFunction)) {
            targetSize = callInst->getArgOperand(0);
        }
        //HZ: allocation functions usually only return an i8* pointer, we'd better try best to infer the real
        //allocation type here from the context.
        //TODO: verify the inferred type w/ the "size" arg if available. 
        Type *objTy = InstructionUtils::inferPointeeTy(callInst);
        if (!objTy) {
            //This is very unlikely...
#ifdef DEBUG_CREATE_HEAP_OBJ
            dbgs() << "AliasFuncHandlerCallback::createNewHeapObject(): failed to infer the return type!\n";
#endif
            objTy = targetFunction->getReturnType();
            if (objTy && objTy->isPointerTy()) {
                objTy = objTy->getPointerElementType();
            }
        }
#ifdef DEBUG_CREATE_HEAP_OBJ
        dbgs() << "AliasFuncHandlerCallback::createNewHeapObject(): heap obj type to create: " << InstructionUtils::getTypeName(objTy) << "\n";
#endif
        AliasObject *targetObj = new HeapLocation(callInstLoc, objTy, targetSize,
                                                  this->targetChecker->is_kmalloc_function(targetFunction));
        if(this->targetChecker->is_kmalloc_function(targetFunction)) {
            // OK, this is kmalloc function, now check if this is kzmalloc?
            // TODO: the flag identification previosuly relies on Range Analysis, which
            // scans the whole module and thus can be expensive for large modules.
            // Now we decide to get rid of the range analysis, and on the other hand, for
            // now we also have little use of the information of whether a "kmalloc" is a 
            // "kzmalloc", so we delete the previous flag identification code here.
            // In the future if we want to re-enable this identification, we should consider
            // to use our variable constraint analysis (in our path analysis) instead.
            //Value *kmalloc_flag = callInst->getArgOperand(1);
        } else {
            targetObj->is_initialized = true;
            targetObj->initializingInstructions.insert(callInst);
        }

        //HZ: we also need to treat heap objects as taint source...
        //Useless now for UAF detection..
        //targetObj->setAsTaintSrc(callInstLoc,true);

        PointerPointsTo *newPointsTo = new PointerPointsTo(callInst,targetObj,0,callInstLoc,false);
        std::set<PointerPointsTo*> *newPointsToInfo = new std::set<PointerPointsTo*>();
        newPointsToInfo->insert(newPointsToInfo->end(), newPointsTo);
        return newPointsToInfo;
    }
}
