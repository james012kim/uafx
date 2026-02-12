//
// common_cg.h - Shared utilities for call-graph-based entry point identification (v2/v3)
//
#ifndef COMMON_CG_H
#define COMMON_CG_H

#include <iostream>
#include <fstream>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <cassert>

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Bitcode/BitcodeReader.h"

using namespace llvm;

// Get the source file name for a function from its debug info.
static std::string getFunctionFileName(Function *F) {
    SmallVector<std::pair<unsigned, MDNode*>, 4> MDs;
    F->getAllMetadata(MDs);
    for (auto &MD : MDs) {
        if (MDNode *N = MD.second) {
            if (auto *subProgram = dyn_cast<DISubprogram>(N)) {
                return subProgram->getFilename().str();
            }
        }
    }
    return "";
}

// Output an entry point in v1-compatible format: TYPE:FUNC_NAME:SOURCE_FILE
static void ffprintf(FILE *of, Function *func, const char *ty) {
    if (!of || !func || !ty) {
        return;
    }
    std::string ff = getFunctionFileName(func);
    fprintf(of, "%s:%s:%s\n", ty, func->getName().str().c_str(), ff.c_str());
}

// Load an LLVM module from a bitcode file.
static std::unique_ptr<Module> loadModule(const char *bcFile, LLVMContext &context) {
    ErrorOr<std::unique_ptr<MemoryBuffer>> fileOrErr = MemoryBuffer::getFileOrSTDIN(bcFile);
    if (std::error_code ec = fileOrErr.getError()) {
        std::cerr << "[!] Error opening bitcode file: " << ec.message() << "\n";
        return nullptr;
    }
    Expected<std::unique_ptr<Module>> moduleOrErr =
        parseBitcodeFile(fileOrErr.get()->getMemBufferRef(), context);
    if (!moduleOrErr) {
        std::cerr << "[!] Failed to parse bitcode file!\n";
        return nullptr;
    }
    return std::move(moduleOrErr.get());
}

// Determine whether a function should be excluded from the call graph.
static bool shouldSkipFunction(Function *F) {
    if (!F) return true;
    if (F->isDeclaration()) return true;
    if (F->isIntrinsic()) return true;
    if (!F->hasName()) return true;
    StringRef name = F->getName();
    // Skip LLVM internal functions
    if (name.startswith("llvm.")) return true;
    return false;
}

// Strip LLVM numeric suffix from struct names (e.g., "struct.A.0" -> "struct.A").
// Replicates the logic in InstructionUtils::trim_num_suffix.
static std::string trimNumericSuffix(const std::string &s) {
    size_t nd = s.rfind('.');
    if (nd == std::string::npos) return s;
    std::string suffix = s.substr(nd + 1);
    // Check if the entire suffix is numeric
    if (suffix.empty()) return s;
    bool allDigits = true;
    for (char c : suffix) {
        if (!isdigit(c)) { allDigits = false; break; }
    }
    if (allDigits) {
        return s.substr(0, nd);
    }
    return s;
}

// Simple Call Graph representation using adjacency lists.
struct SimpleCallGraph {
    // F -> set of functions F calls (outgoing edges)
    std::map<Function*, std::set<Function*>> callees;
    // F -> set of functions that call F (incoming edges)
    std::map<Function*, std::set<Function*>> callers;
    // All function nodes
    std::set<Function*> nodes;

    // Statistics
    size_t numEdges = 0;
    size_t numDirectEdges = 0;
    size_t numIndirectCallSites = 0;
    size_t numResolvedIndirectCalls = 0;
    size_t numIndirectEdges = 0;

    void addNode(Function *f) {
        if (f) nodes.insert(f);
    }

    // Add a directed edge from -> to. Returns true if the edge is new.
    bool addEdge(Function *from, Function *to) {
        if (!from || !to) return false;
        addNode(from);
        addNode(to);
        if (callees[from].insert(to).second) {
            callers[to].insert(from);
            numEdges++;
            return true;
        }
        return false;
    }

    // Get functions with in-degree 0 (no function calls them = top callers).
    std::set<Function*> getTopCallers() {
        std::set<Function*> result;
        for (Function *f : nodes) {
            if (callers.find(f) == callers.end() || callers[f].empty()) {
                result.insert(f);
            }
        }
        return result;
    }

    // Print call graph statistics to stderr.
    void printStats(const char *tag, size_t totalFuncsInModule) {
        std::set<Function*> tc = getTopCallers();
        std::cerr << "[" << tag << "] === Call Graph Statistics ===" << std::endl;
        std::cerr << "[" << tag << "] Total functions in module: " << totalFuncsInModule << std::endl;
        std::cerr << "[" << tag << "] Call graph nodes: " << nodes.size() << std::endl;
        std::cerr << "[" << tag << "] Direct call edges: " << numDirectEdges << std::endl;
        std::cerr << "[" << tag << "] Indirect call sites: " << numIndirectCallSites << std::endl;
        if (numResolvedIndirectCalls > 0) {
            std::cerr << "[" << tag << "] Resolved indirect call sites: " << numResolvedIndirectCalls << std::endl;
            std::cerr << "[" << tag << "] Indirect call edges added: " << numIndirectEdges << std::endl;
        }
        std::cerr << "[" << tag << "] Total edges: " << numEdges << std::endl;
        std::cerr << "[" << tag << "] Top callers (entry points): " << tc.size() << std::endl;
    }
};

static void print_usage(const char *prog_name) {
    std::cerr << "[!] Identifies entry points from a call graph in the provided bitcode file.\n";
    std::cerr << "[?] " << prog_name << " <llvm_linked_bit_code_file> <output_txt_file>\n";
}

#endif // COMMON_CG_H
