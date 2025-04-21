#include "qemu.h"

hp_address add_breakpoint(uint64_t addr, void (*h)(void)) {
    if (!addr)
        return addr;
    gdb_breakpoint_insert(&cpu0, GDB_BREAKPOINT_HW, addr, 0x1000, h);
    return addr;
}

void __apply_breakpoints_linux() { }

void __apply_syscall_hooks() { }
