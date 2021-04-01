#ifndef MEMFLOW_WIN32_HLAPI_H
#define MEMFLOW_WIN32_HLAPI_H

#include "memflow_cpp.h"
#include "memflow_win32.h"
#include "binddestr.h"

#ifndef NO_STL_CONTAINERS
#include <vector>
// Maximum number of entries allowed in the returned lists
#ifndef AUTO_VEC_SIZE
#define AUTO_VEC_SIZE 2048
#endif
#endif

struct c_kernel;

struct c_win32_module_info
    : BindDestr<Win32ModuleInfo, module_info_free>
{
    c_win32_module_info(Win32ModuleInfo *modinfo)
        : BindDestr(modinfo) {}

    WRAP_FN_TYPE(c_os_process_module_info, module, info_trait);
};

struct c_win32_process
    : BindDestr<Win32Process, process_free>
{
    c_win32_process(Win32Process *process)
        : BindDestr(process) {}

    c_win32_process(c_kernel &kernel, Win32ProcessInfo *info);

    WRAP_FN_TYPE(c_win32_module_info, process, module_info);
    WRAP_FN_TYPE(c_virtual_memory, process, virt_mem);
};

struct c_win32_process_info
    : BindDestr<Win32ProcessInfo, process_info_free>
{
    c_win32_process_info(Win32ProcessInfo *info)
        : BindDestr(info) {}

    WRAP_FN_TYPE(COsProcessInfo, process_info, trait);
    WRAP_FN(process_info, dtb);
    WRAP_FN(process_info, section_base);
    WRAP_FN(process_info, wow64);
    WRAP_FN(process_info, peb);
    WRAP_FN(process_info, peb_native);
    WRAP_FN(process_info, peb_wow64);
    WRAP_FN(process_info, teb);
    WRAP_FN(process_info, teb_wow64);
    WRAP_FN(process_info, module_info);
    WRAP_FN(process_info, module_info_native);

    inline operator COsProcessInfo() {
        return this->trait();
    }
};

struct c_kernel
    : BindDestr<Kernel, kernel_free>
{
    c_kernel(Kernel *kernel)
        : BindDestr(kernel) {}

    c_kernel(c_cloneable_physical_memory &mem)
        : BindDestr(kernel_build(mem.invalidate())) {}

    c_kernel(
        c_cloneable_physical_memory &mem,
        uint64_t page_cache_time_ms,
        PageType page_cache_flags,
        uintptr_t page_cache_size_kb,
        uint64_t vat_cache_time_ms,
        uintptr_t vat_cache_entries
    ) : BindDestr(kernel_build_custom(
            mem.invalidate(),
            page_cache_time_ms,
            page_cache_flags,
            page_cache_size_kb,
            vat_cache_time_ms,
            vat_cache_entries
        )) {}

    WRAP_FN_TYPE(c_kernel, kernel, clone);
    WRAP_FN_TYPE_INVALIDATE(c_cloneable_physical_memory, kernel, destroy);
    WRAP_FN(kernel, start_block);
    WRAP_FN(kernel, winver);
    WRAP_FN(kernel, winver_unmasked);
    WRAP_FN(kernel, eprocess_list);
    WRAP_FN(kernel, process_info_list);
    WRAP_FN_TYPE(c_win32_process_info, kernel, kernel_process_info);
    WRAP_FN_TYPE(c_win32_process_info, kernel, process_info_from_eprocess);
    WRAP_FN_TYPE(c_win32_process_info, kernel, process_info);
    WRAP_FN_TYPE(c_win32_process_info, kernel, process_info_pid);
    WRAP_FN_TYPE_INVALIDATE(c_win32_process, kernel, into_process);
    WRAP_FN_TYPE_INVALIDATE(c_win32_process, kernel, into_process_pid);
    WRAP_FN_TYPE_INVALIDATE(c_win32_process, kernel, into_kernel_process);

#ifndef NO_STL_CONTAINERS
    // Manual eprocess_list impl
    std::vector<Address> eprocess_vec(size_t max_size) {
        Address *buf = (Address *)malloc(sizeof(Address *) * max_size);
        std::vector<Address> ret;

        if (buf) {
            size_t size = kernel_eprocess_list(this->inner, buf, max_size);

            for (size_t i = 0; i < size; i++)
                ret.push_back(buf[i]);

            free(buf);
        }

        return ret;
    }

    std::vector<Address> eprocess_vec() {
        return this->eprocess_vec(AUTO_VEC_SIZE);
    }

    // Manual process_info_list impl
    std::vector<c_win32_process_info> process_info_vec(size_t max_size) {
        Win32ProcessInfo **buf = (Win32ProcessInfo **)malloc(sizeof(Win32ProcessInfo *) * max_size);
        std::vector<c_win32_process_info> ret;

        if (buf) {
            size_t size = kernel_process_info_list(this->inner, buf, max_size);

            for (size_t i = 0; i < size; i++)
                ret.push_back(c_win32_process_info(buf[i]));

            free(buf);
        }

        return ret;
    }

    std::vector<c_win32_process_info> process_info_vec() {
        return this->process_info_vec(AUTO_VEC_SIZE);
    }
#endif
};

// Extra constructors we couldn't define inside the classes
c_win32_process::c_win32_process(c_kernel &kernel, Win32ProcessInfo *info)
    : BindDestr(process_with_kernel(kernel.invalidate(), info)) {}

#endif
