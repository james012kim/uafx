"""
This script clones and setups llvm and friends in the provided folder.
"""

import argparse
from multiprocessing import cpu_count
import os
import sys


def log_info(*args):
    log_str = "[*] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    print(log_str)


def log_error(*args):
    log_str = "[!] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    print(log_str)


def log_warning(*args):
    log_str = "[?] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    print(log_str)


def log_success(*args):
    log_str = "[+] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    print(log_str)
    

LLVM_GIT_HUB_BASE = "https://github.com/llvm/llvm-project/"
#https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-14.0.4.tar.gz
LLVM_GIT_SRC_BASE = "https://github.com/llvm/llvm-project/archive/refs/tags/"


def setup_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-b', action='store', dest='target_branch', default='14.0.4',
                        help='Branch (i.e. version) of the LLVM to setup. Default: 14.0.4')

    parser.add_argument('-o', action='store', dest='output_folder',
                        help='Folder where everything needs to be setup.')

    return parser


def usage():
    log_error("Invalid Usage.")
    log_error("Run: python ", __file__, "--help", ", to know the correct usage.")
    sys.exit(-1)


def main():
    arg_parser = setup_args()
    parsed_args = arg_parser.parse_args()
    base_output_dir = os.path.join(parsed_args.output_folder, "llvm")
    backup_dir = os.getcwd()
    os.system('mkdir -p ' + str(base_output_dir))
    os.chdir(base_output_dir)
    # First download the LLVM src tarball.
    target_branch = parsed_args.target_branch
    tarball_name = "llvmorg-" + target_branch + ".tar.gz"
    llvm_src_tarball_url = LLVM_GIT_SRC_BASE + tarball_name
    log_info("Downloading LLVM src tarball...")
    os.system("wget " + llvm_src_tarball_url)
    log_info("Tarball downloaded, now extracting...")
    os.system("tar -xzvf " + tarball_name)
    log_info("Extracted, now trying to build LLVM and related stuff..")
    os.chdir("llvm-project-llvmorg-" + target_branch)
    # Note that the compilers to build llvm can be specified by extra cmake options:
    # e.g., -DCMAKE_C_COMPILER="clang" -DCMAKE_CXX_COMPILER="clang++"
    os.system("cmake -S llvm -B build -G \"Unix Makefiles\" -DLLVM_ENABLE_PROJECTS=\"clang\" -DLLVM_ENABLE_RUNTIMES=\"libcxx;libcxxabi;compiler-rt;openmp\" -DCMAKE_BUILD_TYPE=\"RelWithDebInfo\" -DCMAKE_C_COMPILER=\"clang\" -DCMAKE_CXX_COMPILER=\"clang++\"")
    os.chdir("build")
    build_dir = os.getcwd()
    multi_proc_count = cpu_count()
    if multi_proc_count > 0:
        log_info("Building in multiprocessing mode on ", multi_proc_count, " cores.")
        os.system('make -j' + str(multi_proc_count))
    else:
        log_info("Building in single core mode.")
        os.system('make')
    log_info("Build process finished.")
    print("")
    os.chdir(backup_dir)
    with open('env.sh','w') as ef:
        ef.write("export LLVM_ROOT=" + build_dir + "\n")
        ef.write("export PATH=$LLVM_ROOT/bin:$PATH")
    log_success("IMPORTANT: We have generated the " + backup_dir + "/env.sh which will set environment variables for UAFX.")
    log_success("IMPORTANT: Be sure to set the ENV variables before building/using UAFX, with \"source " + backup_dir + "/env.sh\".")
    print("")
    log_success("Setup Complete.")

if __name__ == "__main__":
    main()