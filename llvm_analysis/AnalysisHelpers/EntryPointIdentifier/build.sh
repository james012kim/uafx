#!/usr/bin/env bash
BASEDIR=$(dirname "$0")
LLVM_FLAGS=$(llvm-config --cxxflags --libs --ldflags --system-libs)

# v1 (original: structure-based identification)
clang++ $BASEDIR/src/main.cpp -fpermissive -o $BASEDIR/entry_point_handler $LLVM_FLAGS

# v2 (call graph: direct calls only, top callers as entry points)
clang++ $BASEDIR/src/main_v2.cpp -fpermissive -o $BASEDIR/entry_point_handler_v2 $LLVM_FLAGS

# v3 (call graph + MLTA: indirect call resolution via Multi-Layer Type Analysis)
clang++ $BASEDIR/src/main_v3.cpp -fpermissive -o $BASEDIR/entry_point_handler_v3 $LLVM_FLAGS
