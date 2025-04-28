#!/bin/bash
#To run the static analysis on the target program.
#$1: ".bc" file
#$2: entry function name/entry config file

nohup opt -load llvm_analysis/MainAnalysisPasses/build_dir/SoundyAliasAnalysis/libSoundyAliasAnalysis.so -enable-new-pm=0 -dr_checker -entryConfig=$2 $1 -o /dev/null >$2.log 2>&1 &
