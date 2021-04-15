#ifndef MEMFLOW_HLAPI_H
#define MEMFLOW_HLAPI_H

#include "memflow.h"
#include "binddestr.h"

#ifndef NO_STL_CONTAINERS
#include <string>
#ifndef AUTO_STRING_SIZE
#define AUTO_STRING_SIZE 128
#endif
#endif

struct c_connector_inventory
    : BindDestr<ConnectorInventory, inventory_free>
{
    c_connector_inventory(ConnectorInventory *inv)
        : BindDestr(inv) {}

    c_connector_inventory()
        : c_connector_inventory(::inventory_scan()) {}

    c_connector_inventory(const char *path)
        : c_connector_inventory(::inventory_scan_path(path)) {}

    WRAP_FN(inventory, add_dir);
    WRAP_FN(inventory, create_connector);
};

struct CPhysicalMemory
    : BindDestr<PhysicalMemoryObj, phys_free>
{
    CPhysicalMemory(PhysicalMemoryObj *mem)
        : BindDestr(mem) {}

    WRAP_FN_RAW(phys_read_raw_list);
    WRAP_FN_RAW(phys_write_raw_list);
    WRAP_FN_RAW(phys_metadata);
    WRAP_FN_RAW(phys_read_raw_into);
    WRAP_FN_RAW(phys_read_u32);
    WRAP_FN_RAW(phys_read_u64);
    WRAP_FN_RAW(phys_write_raw);
    WRAP_FN_RAW(phys_write_u32);
    WRAP_FN_RAW(phys_write_u64);

    template<typename T>
    T phys_read(PhysicalAddress address) {
        T data;
        this->phys_read_raw_into(address, (uint8_t *)&data, sizeof(T));
        return data;
    }

    template<typename T>
    int32_t phys_write(PhysicalAddress address, const T &data) {
        return this->phys_write_raw(address, (const uint8_t *)&data, sizeof(T));
    }
};

struct c_cloneable_physical_memory
    : BindDestr<CloneablePhysicalMemoryObj, connector_free>
{
    c_cloneable_physical_memory(CloneablePhysicalMemoryObj *mem)
        : BindDestr(mem) {}

    WRAP_FN(connector, clone);
    WRAP_FN_RAW_TYPE(CPhysicalMemory, downcast_cloneable);
};

struct c_virtual_memory
    : BindDestr<VirtualMemoryObj, virt_free>
{
    c_virtual_memory(VirtualMemoryObj *virt_mem)
        : BindDestr(virt_mem) {}

    WRAP_FN_RAW(virt_read_raw_list);
    WRAP_FN_RAW(virt_write_raw_list);
    WRAP_FN_RAW(virt_read_raw_into);
    WRAP_FN_RAW(virt_read_u32);
    WRAP_FN_RAW(virt_read_u64);
    WRAP_FN_RAW(virt_write_raw);
    WRAP_FN_RAW(virt_write_u32);
    WRAP_FN_RAW(virt_write_u64);

    template<typename T>
    T read(Address address) {
        T data;
        this->virt_read_raw_into(address, (uint8_t *)&data, sizeof(T));
        return data;
    }

    template<typename T>
    int32_t write(Address address, const T &data) {
        return this->virt_write_raw(address, (const uint8_t *)&data, sizeof(T));
    }
};

struct CArchitecture
    : BindDestr<ArchitectureObj, arch_free>
{
    CArchitecture(ArchitectureObj *arch)
        : BindDestr(arch) {}

    WRAP_FN(arch, bits);
    WRAP_FN(arch, endianess);
    WRAP_FN(arch, page_size);
    WRAP_FN(arch, size_addr);
    WRAP_FN(arch, address_space_bits);
    WRAP_FN_RAW(is_x86_arch);
};

struct COsProcessInfo
    : BindDestr<OsProcessInfoObj, os_process_info_free>
{
    COsProcessInfo(OsProcessInfoObj *info)
        : BindDestr(info) {}

    WRAP_FN(os_process_info, address);
    WRAP_FN(os_process_info, pid);
    WRAP_FN(os_process_info, name);
    WRAP_FN_TYPE(CArchitecture, os_process_info, sys_arch);
    WRAP_FN_TYPE(CArchitecture, os_process_info, proc_arch);

#ifndef NO_STL_CONTAINERS
    std::string name_string(size_t max_size) {
        char *buf = (char *)malloc(max_size);
        if (buf) {
            this->name(buf, max_size);
            std::string ret = std::string(buf);
            free(buf);
            return ret;
        } else {
            return std::string();
        }
    }

    std::string name_string() {
        char buf[AUTO_STRING_SIZE];
        size_t ret = this->name(buf, AUTO_STRING_SIZE);
        return std::string(buf);
    }
#endif
};

struct c_os_process_module_info
    : BindDestr<OsProcessModuleInfoObj, os_process_module_free>
{
    c_os_process_module_info(OsProcessModuleInfoObj *modinfo)
        : BindDestr(modinfo) {}

    WRAP_FN(os_process_module, address);
    WRAP_FN(os_process_module, parent_process);
    WRAP_FN(os_process_module, base);
    WRAP_FN(os_process_module, size);
    WRAP_FN(os_process_module, name);

#ifndef NO_STL_CONTAINERS
    std::string name_string(size_t max_size) {
        char *buf = (char *)malloc(max_size);
        if (buf) {
            this->name(buf, max_size);
            std::string ret = std::string(buf);
            free(buf);
            return ret;
        } else {
            return std::string();
        }
    }

    std::string name_string() {
        char buf[AUTO_STRING_SIZE];
        this->name(buf, AUTO_STRING_SIZE);
        return std::string(buf);
    }
#endif
};

#endif
