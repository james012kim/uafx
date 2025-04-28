//
// Created by machiry on 12/4/16.
//
#include "KernelFunctionChecker.h"
using namespace llvm;

namespace DRCHECKER {

    // These are allocators
    const std::set<std::string> KernelFunctionChecker::known_allocators{"__kmalloc", "kmem_cache_alloc",
                                                                        "mempool_alloc", "kmalloc", 
                                                                        "__get_free_pages", "get_free_pages",
                                                                        "__get_free_page", "get_free_page",
                                                                        "__vmalloc", "vmalloc",
                                                                        "alloc_percpu", "__alloc_percpu",
                                                                        "alloc_bootmem"};

    // these are initializers
    const std::set<std::string> KernelFunctionChecker::zero_initializers{"__kmalloc"};
    const std::set<std::string> KernelFunctionChecker::memset_function_names{"memset"};
    // copy to user function.
    const std::set<std::string> KernelFunctionChecker::copy_out_function_names{"__copy_to_user", "copy_to_user"};
    // init functions
    const std::set<std::string> KernelFunctionChecker::init_section_names{".init.text"};
    // memcpy functions: for points to and taint propagation.
    const std::set<std::string> KernelFunctionChecker::memcpy_function_names{"memcpy", "strcpy", "strncpy",
                                                                             "strcat", "strncat", "strlcpy",
                                                                             "strlcat"};

    const std::set<std::string> KernelFunctionChecker::atoiLikeFunctions{"kstrto", "simple_strto"};
    // fd creation function.
    const std::set<std::string> KernelFunctionChecker::fd_creation_function_names{"anon_inode_getfd","anon_inode_getfile"};
    // memdup function
    const std::set<std::string> KernelFunctionChecker::memdup_function_names{"memdup"};
    // free function name -> freed pointer arg
    std::map<std::string, std::vector<long>> KernelFunctionChecker::free_function_arg_map = {
        {"free", {0}},
        {"kfree", {0}},
        {"kzfree", {0}},
    };

    // lock/unlock function name -> the pointer arg to the lock obj.
    //NOTE: the function names here are all prefixes,
    //as long as a function name (excluding the leading '_') starts with one of these prefixes,
    //it will be a match. We make it like this because there are many lock/unlock function
    //families with the same prefix (e.g., "raw_spin_lock" and "raw_spin_lock_irqsave",
    //"mutex_lock" and "mutex_lock_nested").
    std::map<std::string, std::vector<long>> KernelFunctionChecker::lock_function_arg_map = {
        {"mutex_lock", {0}},
        {"mutex_unlock", {0}},
        {"spin_lock", {0}},
        {"spin_unlock", {0}},
        {"raw_spin_lock", {0}},
        {"raw_spin_unlock", {0}},
        {"pthread_mutex_lock", {0}},
        {"pthread_mutex_unlock", {0}},
        {"down_read", {0}},
        {"up_read", {0}},
        {"down_write", {0}},
        {"up_write", {0}},
        {"console_lock", {}},
        {"console_unlock", {}},
    };

    //2N: lock function, 2N+1: the paired unlock function.
    //TODO: there are still two variants in the "down_read/write" family
    //with "_trylock" and "_non_owner" suffixes, for which I'm still unclear about
    //their semantics and lock/unlock usages.
    std::vector<std::string> KernelFunctionChecker::lock_func_pair = {
        "mutex_lock","mutex_unlock",
        "mutex_lock_nested","mutex_unlock",
        "_raw_spin_lock","_raw_spin_unlock",
        "_raw_spin_lock_irq","_raw_spin_unlock_irq",
        "_raw_spin_lock_irqsave","_raw_spin_unlock_irqrestore",
        "pthread_mutex_lock","pthread_mutex_unlock",
        "down_read","up_read",
        "down_read_nested","up_read",
        "down_write","up_write",
        "down_write_nested","up_write",
        "console_lock","console_unlock",
    };

    bool KernelFunctionChecker::is_debug_function(const Function *targetFunction) {
        if(targetFunction->hasName()) {
            std::string currFuncName = targetFunction->getName().str();
            if(currFuncName.find("llvm.dbg") != std::string::npos) {
                return true;
            }

        }
        return false;
    }

    bool KernelFunctionChecker::is_init_function(const Function *targetFunction) {
        if(!targetFunction->isDeclaration()) {
            for(const std::string &curr_sec : KernelFunctionChecker::init_section_names) {
                if( (!targetFunction->getSection().empty()) && targetFunction->getSection().size() &&
                   (curr_sec.find(targetFunction->getSection().str()) != std::string::npos)) {
                    return true;
                }
            }
        }
        return false;
    }

    bool KernelFunctionChecker::is_copy_out_function(const Function *targetFunction) {
        if(targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            for (const std::string &curr_func:KernelFunctionChecker::copy_out_function_names) {
                if (func_name.find(curr_func.c_str()) != std::string::npos) {
                    return true;
                }
            }
        }
        return false;
    }

    bool KernelFunctionChecker::is_kmalloc_function(const Function *targetFunction) {
        if(targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            for (const std::string &curr_func:KernelFunctionChecker::zero_initializers) {
                if (func_name.find(curr_func.c_str()) != std::string::npos) {
                    return true;
                }
            }
        }
        return false;
    }

    bool KernelFunctionChecker::is_memset_function(const Function *targetFunction) {
        if(targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            for (const std::string &curr_func:KernelFunctionChecker::memset_function_names) {
                if (func_name.find(curr_func.c_str()) != std::string::npos) {
                    return true;
                }
            }
        }
        return false;
    }
    
    bool KernelFunctionChecker::is_function_allocator(const Function *targetFunction) {
        if(targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            for (const std::string &curr_func : KernelFunctionChecker::known_allocators) {
                if (func_name.find(curr_func.c_str()) != std::string::npos) {
                    return true;
                }
            }
        }
        return false;
    }

    bool KernelFunctionChecker::is_custom_function(const Function *targetFunction) {
        // is this a kernel function and returns a pointer?
        return targetFunction->isDeclaration() && targetFunction->getReturnType()->isPointerTy();
    }

    bool KernelFunctionChecker::is_memcpy_function(const Function *targetFunction) {
        if(targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            for (const std::string &curr_func : KernelFunctionChecker::memcpy_function_names) {
                if (func_name.find(curr_func.c_str()) != std::string::npos) {
                    return true;
                }
            }
        }
        return false;
    }

    std::vector<long> KernelFunctionChecker::get_memcpy_arguments(const Function *targetFunction) {
        std::vector<long> memcpy_args;
        if(this->is_memcpy_function(targetFunction)) {
            // src argument is the second parameter
            memcpy_args.push_back(1);
            // dst argument is the first parameter
            memcpy_args.push_back(0);
            return memcpy_args;
        }
        // should never reach here..make sure that you call is_memcpy_function function
        // before this.
        assert(false);
        return memcpy_args;
    }

    std::vector<long> KernelFunctionChecker::get_freed_arguments(const Function *targetFunction) {
        if (this->is_free_function(targetFunction)) {
            return KernelFunctionChecker::free_function_arg_map[targetFunction->getName().str()];
        }else {
            dbgs() << "KernelFunctionChecker::get_freed_arguments(): not a free function!\n";
        }
        std::vector<long> t;
        return t;
    }

    std::vector<long> KernelFunctionChecker::get_lock_arguments(const Function *targetFunction) {
        std::vector<long> t;
        if (targetFunction && targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            size_t i = func_name.find_first_not_of('_');
            if (i == std::string::npos) {
                return t;
            }
            if (i) {
                func_name = func_name.substr(i);
            }
            for (auto &e : KernelFunctionChecker::lock_function_arg_map) {
                const std::string &cand = e.first;
                //The cand should be common (and short) strings usually used as and appeared
                //in lock/unlock functions names (e.g., "mutext_lock" and "mutext_lock_nested").
                if (func_name.find(cand) == 0) {
                    return e.second;
                }
            }
        }
        return t;
    }

    std::set<std::string> KernelFunctionChecker::get_paired_lock_funcs(const std::string &fn,
                                                                       bool *is_lock) {
        std::set<std::string> fns;
        for (int i = 0; i + 1 < KernelFunctionChecker::lock_func_pair.size(); i += 2) {
            if (fn == KernelFunctionChecker::lock_func_pair[i]) {
                if (is_lock) {
                    *is_lock = true;
                }
                fns.insert(KernelFunctionChecker::lock_func_pair[i+1]);
            }else if (fn == KernelFunctionChecker::lock_func_pair[i+1]) {
                if (is_lock) {
                    *is_lock = false;
                }
                fns.insert(KernelFunctionChecker::lock_func_pair[i]);
            }
        }
        return fns;
    }

    bool KernelFunctionChecker::is_taint_initiator(const Function *targetFunction) {
        if(targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            return func_name.find("copy_from_user") != std::string::npos ||
                    func_name == "simple_write_to_buffer";
        }
        return false;
    }

    std::set<long> KernelFunctionChecker::get_tainted_arguments(const Function *targetFunction) {
        std::set<long> tainted_args;
        if (targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            if(func_name.find("copy_from_user") != std::string::npos ||
               func_name == "simple_write_to_buffer") {
                // first argument will get tainted.
                tainted_args.insert(tainted_args.end(), 0);
                return tainted_args;
            }
        }
        // should never reach here..make sure that you call is_taint_initiator function
        // before this.
        assert(false);
        return tainted_args;
    }

    bool KernelFunctionChecker::is_atoi_function(const Function *targetFunction) {
        if(targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string funcName = targetFunction->getName().str();
            for (const std::string &curr_func:KernelFunctionChecker::atoiLikeFunctions) {
                if(funcName.compare(0, curr_func.length(), curr_func) == 0) {
                    return true;
                }
            }
        }
        return false;
    }

    bool KernelFunctionChecker::is_sscanf_function(const Function *targetFunction) {
        std::string sscanf_func("sscanf");
        if(targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string funcName = targetFunction->getName().str();
            return funcName.compare(0, sscanf_func.length(), sscanf_func) == 0;
        }
        return false;

    }
    
    bool KernelFunctionChecker::is_memdup_function(const Function *targetFunction) {
        if(targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            for (const std::string &curr_func:KernelFunctionChecker::memdup_function_names) {
                if (func_name.find(curr_func.c_str()) != std::string::npos) {
                    return true;
                }
            }
        }
        return false;
    }

    bool KernelFunctionChecker::is_free_function(const Function *targetFunction) {
        if (targetFunction && targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            return (KernelFunctionChecker::free_function_arg_map.find(func_name) != KernelFunctionChecker::free_function_arg_map.end());
        }
        return false;
    }

    bool KernelFunctionChecker::is_lock_function(const Function *targetFunction) {
        if (targetFunction && targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            size_t i = func_name.find_first_not_of('_');
            if (i == std::string::npos) {
                return false;
            }
            if (i) {
                func_name = func_name.substr(i);
            }
            for (auto &e : KernelFunctionChecker::lock_function_arg_map) {
                const std::string &cand = e.first;
                //The cand should be common (and short) strings usually used as and appeared
                //in lock/unlock functions names (e.g., "mutext_lock" and "mutext_lock_nested").
                if (func_name.find(cand) == 0) {
                    return true;
                }
            }
        }
        return false;
    }

    bool KernelFunctionChecker::is_fd_creation_function(const Function *targetFunction) {
        if(targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            for (const std::string &curr_func:KernelFunctionChecker::fd_creation_function_names) {
                if (func_name.find(curr_func.c_str()) != std::string::npos) {
                    return true;
                }
            }
        }
        return false;
    }

    std::map<long,long> KernelFunctionChecker::get_fd_field_arg_map(const Function *targetFunction) {
        std::map<long,long> fieldArgMap;
        if(targetFunction->isDeclaration() && targetFunction->hasName()) {
            std::string func_name = targetFunction->getName().str();
            if(func_name == "anon_inode_getfd") {
                //func prototype:
                //int anon_inode_getfd(const char *name, const struct file_operations *fops, void *priv, int flags)
                fieldArgMap[3] = 1; //file->f_op
                fieldArgMap[16] = 2; //file->private_data
                return fieldArgMap;
            }
            if(func_name == "anon_inode_getfile") {
                //func prototype:
                //struct file *anon_inode_getfd(const char *name, const struct file_operations *fops, void *priv, int flags)
                fieldArgMap[3] = 1; //file->f_op
                fieldArgMap[16] = 2; //file->private_data
                fieldArgMap[-1] = 0; //this means the func ret should point to the created file struct.
                return fieldArgMap;
            }

        }
        // should never reach here..make sure that you call is_fd_creation_function function
        // before this.
        assert(false);
        return fieldArgMap;
    }

}

