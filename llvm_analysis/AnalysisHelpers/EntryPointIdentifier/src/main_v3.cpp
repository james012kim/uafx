//
// EntryPoint Identifier v3: Call Graph with MLTA (Multi-Layer Type Analysis)
//
// Extends v2 by resolving indirect calls using the TypeDive/MLTA technique:
//   1. Collect where each function is stored as a function pointer (composite
//      type hierarchy, e.g., void (*)(int) | struct.A[field 2] | struct.X[field 0])
//   2. At each indirect call site, trace back through Load->GEP chains to
//      determine the composite type context
//   3. Match call-site type layers against stored function signatures to
//      identify candidate targets
//   4. Add resolved edges to the call graph
//   5. Find top callers (in-degree 0) as entry points
//
// Usage: entry_point_handler_v3 <bitcode_file> <output_file>
//

#include "common_cg.h"
#include <tuple>
#include <algorithm>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Operator.h"

using namespace std;

// ============================================================================
// MLTA Data Structures
// ============================================================================

// A layer in the composite type hierarchy where a function pointer is stored.
struct TypeLayer {
    std::string hostTypeName;  // Struct type name (with numeric suffix trimmed)
    long fieldIndex;           // Field index within the struct
};

// Full MLTA signature: function type + composite type layers
struct MLTASignature {
    FunctionType *funcType;
    std::vector<TypeLayer> layers;  // From innermost (direct container) to outermost
};

// Key for multi-layer index lookup
struct MLTAKey {
    FunctionType *funcType;
    std::string hostTypeName;
    long fieldIndex;

    bool operator<(const MLTAKey &o) const {
        if (funcType != o.funcType) return funcType < o.funcType;
        if (hostTypeName != o.hostTypeName) return hostTypeName < o.hostTypeName;
        return fieldIndex < o.fieldIndex;
    }
};

// ============================================================================
// MLTA Analysis State
// ============================================================================

// Per-function: list of storage signatures (where the function is stored as a fptr)
static std::map<Function*, std::vector<MLTASignature>> funcSignatures;

// Index: FunctionType -> set of candidate functions (type-only match, layer 1)
static std::map<FunctionType*, std::set<Function*>> typeOnlyIndex;

// Index: (FunctionType, StructTypeName, fieldIndex) -> set of candidate functions
static std::map<MLTAKey, std::set<Function*>> multiLayerIndex;

// Statistics
static size_t numStaticSigs = 0;
static size_t numDynamicSigs = 0;

// ============================================================================
// Phase 1: Collect function pointer storage signatures
// ============================================================================

// Get the trimmed struct type name. Returns "" if not a named struct.
static std::string getStructName(Type *ty) {
    StructType *st = dyn_cast<StructType>(ty);
    if (!st || !st->hasName()) return "";
    return trimNumericSuffix(st->getName().str());
}

// Recursively scan a constant for function pointers stored in struct fields.
// parentLayers: the composite type layers leading to this constant (outermost first).
static void scanConstant(Constant *C, std::vector<TypeLayer> parentLayers) {
    if (!C) return;

    ConstantStruct *cs = dyn_cast<ConstantStruct>(C);
    if (cs) {
        Type *ty = cs->getType();
        std::string stName = getStructName(ty);
        if (stName.empty()) return;

        for (unsigned i = 0; i < cs->getNumOperands(); i++) {
            Constant *fieldVal = cs->getOperand(i);
            if (!fieldVal) continue;

            // Strip pointer casts to find the underlying value
            Value *stripped = fieldVal->stripPointerCasts();

            if (Function *func = dyn_cast<Function>(stripped)) {
                if (!func->isDeclaration()) {
                    MLTASignature sig;
                    sig.funcType = func->getFunctionType();
                    // Innermost layer first: this struct at this field
                    TypeLayer layer;
                    layer.hostTypeName = stName;
                    layer.fieldIndex = (long)i;
                    sig.layers.push_back(layer);
                    // Then append parent layers
                    sig.layers.insert(sig.layers.end(), parentLayers.begin(), parentLayers.end());
                    funcSignatures[func].push_back(sig);
                    numStaticSigs++;
                }
            } else if (dyn_cast<ConstantStruct>(fieldVal)) {
                // Recurse into nested struct
                std::vector<TypeLayer> newParent;
                TypeLayer layer;
                layer.hostTypeName = stName;
                layer.fieldIndex = (long)i;
                newParent.push_back(layer);
                newParent.insert(newParent.end(), parentLayers.begin(), parentLayers.end());
                scanConstant(fieldVal, newParent);
            }
            // ConstantArray elements are scanned without adding a meaningful layer
            // since arrays just repeat the same type.
        }
        return;
    }

    ConstantArray *ca = dyn_cast<ConstantArray>(C);
    if (ca) {
        for (unsigned i = 0; i < ca->getNumOperands(); i++) {
            Constant *elem = ca->getOperand(i);
            scanConstant(elem, parentLayers);
        }
    }
}

// Phase 1A: Collect signatures from global variable constant initializers.
static void collectStaticSignatures(Module *m) {
    for (GlobalVariable &GV : m->globals()) {
        if (!GV.hasInitializer()) continue;
        Constant *init = GV.getInitializer();
        std::vector<TypeLayer> emptyLayers;
        scanConstant(init, emptyLayers);
    }
}

// Extract type layers from a GEP instruction/operator.
// Returns layers from innermost (last struct field accessed) to outermost.
static bool extractLayersFromGEP(GEPOperator *gep, std::vector<TypeLayer> &layers) {
    if (!gep) return false;

    Value *basePtr = gep->getPointerOperand();
    if (!basePtr || !basePtr->getType() || !basePtr->getType()->isPointerTy()) return false;

    Type *baseTy = basePtr->getType()->getPointerElementType();

    // Walk through GEP indices to determine struct fields accessed.
    // Index 0 is the pointer offset; index 1+ are field indices.
    Type *curTy = baseTy;
    std::vector<TypeLayer> tempLayers;

    // Skip index 0 (array offset), iterate from index 1
    for (unsigned i = 2; i < gep->getNumOperands(); i++) {
        ConstantInt *CI = dyn_cast<ConstantInt>(gep->getOperand(i));
        if (!CI) break;  // Non-constant index, cannot resolve

        if (StructType *st = dyn_cast<StructType>(curTy)) {
            std::string stName = getStructName(st);
            if (stName.empty()) break;

            long fieldIdx = CI->getZExtValue();
            if (fieldIdx >= (long)st->getNumElements()) break;

            TypeLayer layer;
            layer.hostTypeName = stName;
            layer.fieldIndex = fieldIdx;
            tempLayers.push_back(layer);
            curTy = st->getElementType(fieldIdx);
        } else if (ArrayType *at = dyn_cast<ArrayType>(curTy)) {
            curTy = at->getElementType();
            // Arrays don't add a type layer
        } else {
            break;
        }
    }

    if (tempLayers.empty()) return false;

    // Reverse so innermost is first
    std::reverse(tempLayers.begin(), tempLayers.end());
    layers = tempLayers;
    return true;
}

// Phase 1B: Collect signatures from dynamic store instructions.
// Pattern: store @func, (GEP %base, 0, field_idx)
static void collectDynamicSignatures(Module *m) {
    for (Function &F : *m) {
        if (F.isDeclaration()) continue;
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                StoreInst *si = dyn_cast<StoreInst>(&I);
                if (!si) continue;

                // Check if the stored value is a function (possibly bitcast)
                Value *storedVal = si->getValueOperand();
                if (!storedVal) continue;
                storedVal = storedVal->stripPointerCasts();
                Function *targetFunc = dyn_cast<Function>(storedVal);
                if (!targetFunc || targetFunc->isDeclaration()) continue;

                // Check if the destination is a GEP into a struct field
                Value *destPtr = si->getPointerOperand();
                if (!destPtr) continue;
                destPtr = destPtr->stripPointerCasts();
                GEPOperator *gep = dyn_cast<GEPOperator>(destPtr);
                if (!gep) continue;

                std::vector<TypeLayer> layers;
                if (extractLayersFromGEP(gep, layers)) {
                    MLTASignature sig;
                    sig.funcType = targetFunc->getFunctionType();
                    sig.layers = layers;
                    funcSignatures[targetFunc].push_back(sig);
                    numDynamicSigs++;
                }
            }
        }
    }
}

// ============================================================================
// Phase 2: Build MLTA lookup indices
// ============================================================================

static void buildMLTAIndex() {
    for (auto &entry : funcSignatures) {
        Function *func = entry.first;
        for (auto &sig : entry.second) {
            // Type-only index (layer 1)
            typeOnlyIndex[sig.funcType].insert(func);

            // Multi-layer index using the innermost layer
            if (!sig.layers.empty()) {
                MLTAKey key;
                key.funcType = sig.funcType;
                key.hostTypeName = sig.layers[0].hostTypeName;
                key.fieldIndex = sig.layers[0].fieldIndex;
                multiLayerIndex[key].insert(func);
            }
        }
    }
}

// ============================================================================
// Phase 3: Resolve indirect calls
// ============================================================================

// Check if a function's MLTA signature matches the call-site type layers
// at deeper levels (beyond layer 0 which is already matched by the index).
static bool sigMatchesDeepLayers(const MLTASignature &sig,
                                  const std::vector<TypeLayer> &callSiteLayers) {
    size_t minLen = std::min(sig.layers.size(), callSiteLayers.size());
    // Layer 0 is already matched by the index, check layer 1+
    for (size_t i = 1; i < minLen; i++) {
        if (sig.layers[i].hostTypeName != callSiteLayers[i].hostTypeName) return false;
        if (sig.layers[i].fieldIndex != callSiteLayers[i].fieldIndex) return false;
    }
    return true;
}

// Resolve an indirect call site using MLTA.
// Returns the set of candidate target functions.
static std::set<Function*> resolveIndirectCall(CallBase *cb) {
    std::set<Function*> candidates;
    FunctionType *calledType = cb->getFunctionType();

    // Try to trace back the called operand to get composite type context:
    //   indirect call: call %op
    //   %op = load %ptr
    //   %ptr = GEP %base, 0, fieldIdx
    Value *calledOperand = cb->getCalledOperand();
    if (!calledOperand) {
        // Fallback: type-only match
        auto it = typeOnlyIndex.find(calledType);
        if (it != typeOnlyIndex.end()) candidates = it->second;
        return candidates;
    }
    calledOperand = calledOperand->stripPointerCasts();

    LoadInst *loadInst = dyn_cast<LoadInst>(calledOperand);
    if (loadInst) {
        Value *loadPtr = loadInst->getPointerOperand();
        if (loadPtr) {
            loadPtr = loadPtr->stripPointerCasts();
            GEPOperator *gep = dyn_cast<GEPOperator>(loadPtr);
            if (gep) {
                std::vector<TypeLayer> callSiteLayers;
                if (extractLayersFromGEP(gep, callSiteLayers) && !callSiteLayers.empty()) {
                    // Multi-layer matching: try the innermost layer first
                    MLTAKey key;
                    key.funcType = calledType;
                    key.hostTypeName = callSiteLayers[0].hostTypeName;
                    key.fieldIndex = callSiteLayers[0].fieldIndex;

                    auto it = multiLayerIndex.find(key);
                    if (it != multiLayerIndex.end() && !it->second.empty()) {
                        // Found candidates via multi-layer index
                        // If we have deeper layers, try to further refine
                        if (callSiteLayers.size() > 1) {
                            std::set<Function*> refined;
                            for (Function *f : it->second) {
                                for (auto &sig : funcSignatures[f]) {
                                    if (sig.funcType == calledType &&
                                        !sig.layers.empty() &&
                                        sig.layers[0].hostTypeName == key.hostTypeName &&
                                        sig.layers[0].fieldIndex == key.fieldIndex &&
                                        sigMatchesDeepLayers(sig, callSiteLayers)) {
                                        refined.insert(f);
                                        break;
                                    }
                                }
                            }
                            if (!refined.empty()) return refined;
                        }
                        return it->second;
                    }
                }
            }
        }
    }

    // Fallback: type-only match
    auto it = typeOnlyIndex.find(calledType);
    if (it != typeOnlyIndex.end()) candidates = it->second;
    return candidates;
}

// ============================================================================
// Phase 4: Build the full call graph with MLTA-resolved indirect calls
// ============================================================================

static void buildMLTACallGraph(Module *m, SimpleCallGraph &cg) {
    for (Function &F : *m) {
        if (shouldSkipFunction(&F)) continue;
        cg.addNode(&F);

        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                CallBase *cb = dyn_cast<CallBase>(&I);
                if (!cb) continue;

                Function *callee = cb->getCalledFunction();
                if (callee) {
                    // Direct call
                    if (!shouldSkipFunction(callee)) {
                        if (cg.addEdge(&F, callee)) {
                            cg.numDirectEdges++;
                        }
                    }
                } else {
                    Value *calledOp = cb->getCalledOperand();
                    if (calledOp && !isa<InlineAsm>(calledOp)) {
                        // Indirect call - resolve with MLTA
                        cg.numIndirectCallSites++;
                        std::set<Function*> targets = resolveIndirectCall(cb);
                        if (!targets.empty()) {
                            cg.numResolvedIndirectCalls++;
                            for (Function *target : targets) {
                                if (!shouldSkipFunction(target)) {
                                    if (cg.addEdge(&F, target)) {
                                        cg.numIndirectEdges++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return -1;
    }

    const char *bcFile = argv[1];
    const char *outputFile = argv[2];

    LLVMContext context;
    std::unique_ptr<Module> mod = loadModule(bcFile, context);
    if (!mod) {
        std::cerr << "[!] Failed to load module from: " << bcFile << "\n";
        return -1;
    }
    Module *m = mod.get();

    // Count total functions in the module
    size_t totalFuncs = 0;
    for (Function &F : *m) {
        (void)F;
        totalFuncs++;
    }

    // Phase 1: Collect MLTA signatures
    std::cerr << "[EntryPointIdentifier-v3] Phase 1: Collecting function pointer storage signatures...\n";
    collectStaticSignatures(m);
    collectDynamicSignatures(m);

    // Phase 2: Build MLTA indices
    std::cerr << "[EntryPointIdentifier-v3] Phase 2: Building MLTA indices...\n";
    buildMLTAIndex();

    // Print MLTA statistics
    std::cerr << "[EntryPointIdentifier-v3] === MLTA Statistics ===" << std::endl;
    std::cerr << "[EntryPointIdentifier-v3] Functions with storage signatures: " << funcSignatures.size() << std::endl;
    std::cerr << "[EntryPointIdentifier-v3] Static signatures collected: " << numStaticSigs << std::endl;
    std::cerr << "[EntryPointIdentifier-v3] Dynamic signatures collected: " << numDynamicSigs << std::endl;
    std::cerr << "[EntryPointIdentifier-v3] Type-only index entries: " << typeOnlyIndex.size() << std::endl;
    std::cerr << "[EntryPointIdentifier-v3] Multi-layer index entries: " << multiLayerIndex.size() << std::endl;

    // Phase 3 & 4: Build call graph with MLTA-resolved indirect calls
    std::cerr << "[EntryPointIdentifier-v3] Phase 3-4: Building call graph with MLTA resolution...\n";
    SimpleCallGraph cg;
    buildMLTACallGraph(m, cg);

    // Get top callers (in-degree 0)
    std::set<Function*> topCallers = cg.getTopCallers();

    // Write entry points
    FILE *of = fopen(outputFile, "w");
    if (!of) {
        std::cerr << "[!] Failed to open output file: " << outputFile << "\n";
        return -1;
    }

    for (Function *f : topCallers) {
        ffprintf(of, f, "TOP_CALLER");
    }

    fclose(of);

    // Print call graph statistics
    cg.printStats("EntryPointIdentifier-v3", totalFuncs);

    return 0;
}
