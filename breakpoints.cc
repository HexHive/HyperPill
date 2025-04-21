#include "fuzz.h"
#include <utility>
#include <vector>

/*
 * List of capabilities we want:
 *      Skip a function call. (+ set return value)
 *      Take a jump (even if we don't want to).
 *      Teleport the PC.
 *      Should be based primarily on symbol names
 *      Hook Syscalls
 *
 *  Design. Apis:
 *      PC Hook.
 *      Instruction Hook.
 *      Ctrl-xfer hook?
 *
 *  Call hook sideffects:
 *      Skip the call.
 *      Change the call destination.
 *      Change the call return
 */


/*
 * These breakpoints need to be pretty fast
 */

void apply_breakpoints_linux() {
    // sanitizer stuff
    // _asan_report_store4
    // -> __asan::ReportGenericError or __asan::ReportDoubleFree()
    //     -> __asan::ScopedInErrorReport::ScopedInErrorReport()
    //     -> __asan::ErrorGeneric::ErrorGeneric
    //     -> internal_memcpy(&current_error_, &description, sizeof(current_error_));
    //     -> __asan::ScopedInErrorReport::~ScopedInErrorReport()
    //         -> __asan::DescribeThread()
    //         -> __sanitizer::Die(), abort or exit
    __apply_breakpoints_linux();
    add_breakpoint(sym_to_addr("firecracker", "core::panicking::panic_fmt"), [](hp_instruction *i) {
            fuzz_emu_stop_crash("firecracker: panic");
            });
    add_breakpoint(sym_to_addr("libasan.so", "__asan::ScopedInErrorReport::~ScopedInErrorReport"), [](hp_instruction *i) {
            // every error through asan should reach this
            printf("ASAN error report\n");
            fuzz_stacktrace();
            });
    add_breakpoint(sym_to_addr("vmlinux", "crash_kexec"), [](hp_instruction *i) { 
            printf("kexec crash\n");
            print_stacktrace();
    });
    add_breakpoint(sym_to_addr("vmlinux", "hyp_panic"), [](hp_instruction *i) {
        fuzz_emu_stop_crash("vmlinux: hyp_panic");
    });
    add_breakpoint(sym_to_addr("vmlinux", "panic"), [](hp_instruction *i) {
        fuzz_emu_stop_crash("vmlinux: panic");
    });
    add_breakpoint(sym_to_addr("vmlinux", "__guest_exit_panic"), [](hp_instruction *i) {
        fuzz_emu_stop_crash("vmlinux: __guest_exit_panic");
    });
}

void handle_syscall_hooks(hp_instruction *i)
{
    __handle_syscall_hooks(i);
}
