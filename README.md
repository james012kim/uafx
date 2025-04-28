# UAFX

UAFX is a C static analyzer which can help discover complex use-after-free issues spanning across multiple entry functions (e.g., suppose that the free site and use site locate in two different system calls, connected by subtle alias relationship around global pointers). To achieve this, UAFX employs two major techniques:  

- **Escape-Fetch based Cross-Entry Pointer Analysis**:
UAFX tracks the memory objects *escapes* from the local function to global pointers and *fetched* in the opposite direction, this enables it to identify the aliased memory objects even they appear in different entry functions.  

- **Systematic Partial-Order based UAF Validation**:
Whether an aliased pair of use/free sites make a true UAF case can depend on many subtle and interwined code aspects, such as locks, condition checks, etc. UAFX comprehensively encodes various code asepcts relevant to UAF logic into a unified and extensible partial-order system, which can be solved by a SMT solver (e.g., z3) to decide the UAF feasibility. This helps us reduce the false alarms significantly.

UAFX is built on top of [SUTURE](https://github.com/seclab-ucr/SUTURE/tree/main). More design and implementation details are documented in our research paper: [Statically Discover Cross-Entry Use-After-Free Vulnerabilities in the Linux Kernel](https://www.ndss-symposium.org/wp-content/uploads/2025-559-paper.pdf) published in *NDSS'25*.

## 0x0 Setup  

First clone the repo:  
`~$ git clone https://github.com/uafx/uafx.git uafx`  

Then setup the LLVM environment for UAFX (it's based on LLVM 14):  
`~$ cd uafx`  
`~/uafx$ python setup_uafx.py -o ../uafx_deps`
  
Depending on your hardware, the LLVM setup may take quite some time. After it finishes, a srcipt file named `env.sh` will be generated under the UAFX root folder, it contains commands to set the environment variables used by UAFX.  
**IMPORTANT**: Be sure to activate this `env.sh` every time before building/using UAFX (you can also add its contained commands to *.bashrc* for automatic activation upon shell login)!  
`~/uafx$ source env.sh`

Next, build UAFX:  
`~/uafx$ cd llvm_analysis`  
`~/uafx/llvm_analysis$ ./build.sh`  
Upon a successful build, UAFX is ready to use.

## 0x1 Vulnerability Discovery w/ an Example  

UAFX can be used to discover cross-entry UAF vulnerabilities, in this section we walk through this process w/ an example (e.g., the motivating example as shown in Section II in our [paper](https://www.ndss-symposium.org/wp-content/uploads/2025-559-paper.pdf)).  

### 0x10 Prepare the Input  

To discover vulnerabilities UAFX requires two types of input: (1) the target program compiled to LLVM bitcode (e.g., a *.bc* file), and (2) a configuration file for the target program that manifests its entry functions.  

Let's first prepare the LLVM bitcode for our motivating example:  
`~/uafx$ cd benchmark`  
`~/uafx/benchmark$ ./gen.sh test_uafx_demo`  
**NOTE**: for convenience we provide `gen.sh` to compile a *.c* to *.bc* and *.ll* (human readable LLVM bitcode), with `-O1` optimization level.  
Now we should have the *test_uafx_demo.bc* under the same *benchmark* folder, that's the input program bitcode for UAFX.  

Then it comes to the configuration file, we have already prepared one for the  motivating example:  
```
~/uafx/benchmark$ cat conf_test_uafx_demo  
entry0
entry1
entry2
entry3  
```  
**Explanation**: Each line in the config file specifies one entry function (e.g., the top-level function w/o callers and usually serves as the external interface) in the target program. Check our motivating example in *benchmark/test_uafx_demo.c*, where there are four entry functions (i.e., `entry0() - entry1()`), as listed in the above config file.  

### 0x11 Run the Analysis  

Once the program bitcode and the entry config file are ready, we can run UAFX to discover UAF vulnerabilities:  
`~/uafx$ ./run_nohup.sh benchmark/test_uafx_demo.bc benchmark/conf_test_uafx_demo`  
**Explanation**: *run_nohup.sh* is a simple script invoking the compiled LLVM analysis passes of UAFX:  
```
~/uafx$ ./run_nohup.sh [path/to/program.bc] [path/to/entry_func_config]
```  

Once started, depending on the actual hardware and the complexity of the target program, the required time for UAFX to finish the analysis and vulnerability discovery varies a lot. A simple program like our motivating example usually finishes instantly, though.  
**Decide whether the analysis finishes**: During execution, UAFX keeps logging into a file under the same directory of the *entry config file*, suppose the config file path is */path/to/conf_program*, the log file will be */path/to/conf_program.log*. We can decide whether the analysis finishes by monitoring the log:  
`~/uafx$ grep "Bug Detection Phase finished" /path/to/conf_program.log`  

### 0x12 Inspect the Output  
The aforementioned log file is also UAFX's output, UAFX will embed its discovered potential vulnerabilities in the log file, which can be extracted and organized into a final warning report after the analysis finishes:  
`~/uafx$ ./ext_uaf_warns.sh benchmark/conf_test_uafx_demo.log`  
**Explanation**: *ext_uaf_warns.sh* will extract all warnings (in JSON) embedded in the given log file, re-organize and pretty-print them into the final warning reports. The warning reports will be put into a folder under the same path of the log file, suppose the log file is */path/to/conf_program.log*, the warning report folder will be */path/to/warns-conf_program-yyyy-mm-dd*.  
```
~/uafx$ ls benchmark/warns-conf_test_uafx_demo-2025-04-27/
uaf
```  
In the folder there is a *uaf* file which contains potential UAF issues identified by UAFX. These issues are grouped according to their control/data flow relationship (the grouping logic can be found in *ext_uaf_warns.py*).
```
~/uafx$ cat -n benchmark/warns-conf_test_uafx_demo-2025-04-27/uaf
     1  =========================GROUP 0=========================
     2  #########Summary#########
     3  LOC 0:
     4  (u'test_uafx_demo.c', 16, u'entry0')
     5  LOC 1:
     6  (u'test_uafx_demo.c', 32, u'entry3')
     7  #########################
     8
     9  ++++++++++++++++WARN 0++++++++++++++++
    10  UAFDetector
    11  Flow: Con
    12  ****LOC 0****
    13  #####CTX##### entry0
    14  entry0 (test_uafx_demo.c@11)
    15  #####INST#####
    16  test_uafx_demo.c@16 (entry0 :   call void @free(i8* noundef %1) #10, !dbg !68)
    17  ****LOC 1****
    18  #####CTX##### entry3
    19  entry3 (test_uafx_demo.c@32)
    20  #####INST#####
    21  test_uafx_demo.c@32 (entry3 :   %2 = load i8, i8* %1, align 1, !dbg !97, !tbaa !90)
    22  ****EP 1****
    ......
```  
**Explanation**: At a high level, the warning report contains some warning **groups**, each group contains several **warnings**, and each warning contains two code locations: *LOC 0* frees a memory object, which is accessed later by *LOC 1*, making a potential UAF issue. For each location, UAFX also provides its full calling context, starting from the relevant entry function. The *EP* part contained in the warning is mainly for debug purposes.

Take the above warning report as an example:  
- Line 1: The header line of a warning group.  
- Line 2-7: A summary of the warned use/free locations within the group.  
- Line 9: The header line of a warning, note that the `WARN No.` is local to its group.  
- Line 10: The specific detector used, always "UAFDetector" for UAFX.  
- Line 11: Type of the control flow to trigger this UAF, "con" means it needs multiple entry function invocations, "seq" indicates a simpler sequential UAF case (i.e., use and free are reached within a single entry function invocation).
- Line 12-16: *LOC 0*, the program location that frees the memory object, its calling context is manifested in the *CTX* section, while that freeing instruction itself is in the *INST* section. We list both the source-code location (i.e., file name and line number) and LLVM IR.
- Line 17-21: *LOC 1*, the program location that accesses the (previously freed) memory object, the format is same as *LOC 0*.
- Line 22-..: for debug purposes.

The above warning correctly reports the true UAF issue in our motivating example while avoiding the false alarm that many less sophiscated static UAF detectors may report. More details can be found in Section II in our [paper](https://www.ndss-symposium.org/wp-content/uploads/2025-559-paper.pdf).