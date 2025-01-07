#include "fuzz.h"
#include "qemuapi.h"

static uint64_t add_breakpoint(uint64_t addr, int (*h)(void)) {
    if (!addr)
        return addr;
    printf("Applying breakpoint to: %lx %s\n", addr, addr_to_sym(addr).second.c_str());
    __add_breakpoint(addr, h);
    return addr;
}

void apply_breakpoints_linux() {

    // TODO exit/abort/sanitizer stuff
    add_breakpoint(sym_to_addr("vmlinux", "hyp_panic"), []() {
        fuzz_emu_stop_crash("vmlinux: panic");
        abort();
        return -1;
    });

    add_breakpoint(sym_to_addr("vmlinux", "panic"), []() {
        fuzz_emu_stop_crash("vmlinux: panic");
        abort();
        return -1;
    });
}

void handle_syscall_hooks(hp_instruction *i) { }
