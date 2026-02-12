//
// EntryPoint Identifier v2: Call Graph based (direct calls only)
//
// Builds a call graph considering only direct calls (CallInst/InvokeInst
// where the called function is statically known). Functions with no callers
// (in-degree 0) are identified as entry points ("top callers").
//
// Usage: entry_point_handler_v2 <bitcode_file> <output_file>
//

#include "common_cg.h"

// Build a call graph from the module considering only direct calls.
// Indirect call sites are counted but not resolved.
void buildDirectCallGraph(Module *m, SimpleCallGraph &cg) {
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
                    // Indirect call (skip inline asm)
                    Value *calledOp = cb->getCalledOperand();
                    if (calledOp && !isa<InlineAsm>(calledOp)) {
                        cg.numIndirectCallSites++;
                    }
                }
            }
        }
    }
}

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

    // Count total functions in the module (including declarations)
    size_t totalFuncs = 0;
    for (Function &F : *m) {
        (void)F;
        totalFuncs++;
    }

    // Build the direct call graph
    SimpleCallGraph cg;
    buildDirectCallGraph(m, cg);

    // Get top callers (in-degree 0)
    std::set<Function*> topCallers = cg.getTopCallers();

    // Write entry points in v1-compatible format
    FILE *of = fopen(outputFile, "w");
    if (!of) {
        std::cerr << "[!] Failed to open output file: " << outputFile << "\n";
        return -1;
    }

    for (Function *f : topCallers) {
        ffprintf(of, f, "TOP_CALLER");
    }

    fclose(of);

    // Print statistics to stderr
    cg.printStats("EntryPointIdentifier-v2", totalFuncs);

    return 0;
}
