#include "qemu.h"

void handle_breakpoints(void *i) { assert(0); }

hp_address add_breakpoint(uint64_t addr, void (*h)(void)) {
    if (!addr)
        return addr;
    gdb_breakpoint_insert(QEMU_CPU(0), GDB_BREAKPOINT_HW, addr, 0x1000, h);
    return addr;
}

void __apply_breakpoints_linux() { assert(0); }

void __handle_syscall_hooks(void *i) { assert(0); }
