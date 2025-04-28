#!/bin/bash
LLVM_DIR=$LLVM_ROOT/../cmake
echo "[*] Trying to Run Cmake"
mkdir build_dir
cd build_dir
cmake .. -DCMAKE_C_COMPILER="clang" -DCMAKE_CXX_COMPILER="clang++" -DCMAKE_BUILD_TYPE=RelWithDebInfo
echo "[*] Trying to make"
make -j8
cd ..
