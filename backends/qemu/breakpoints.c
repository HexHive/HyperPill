#include "qemu.h"

uint64_t add_breakpoint(uint64_t addr, int (*h)(void)) {
	if (!addr)
		return addr;
	gdb_breakpoint_insert(QEMU_CPU(0), GDB_BREAKPOINT_HW, addr, 0x1000, h);
	return addr;
}

static int libasan_crash(void) {
	// every error through asan should reach this
	fuzz_stacktrace();
	fuzz_emu_stop_crash("ASAN error report\n");
	vm_stop(RUN_STATE_RESTORE_VM);
	return EXCP_HALTED;
}

static int page_fault_crash(void) {
	fuzz_stacktrace();
	fuzz_emu_stop_crash("page fault report\n");
	vm_stop(RUN_STATE_RESTORE_VM);
	return EXCP_HALTED;
}

static int stack_chk_fail_crash(void) {
	fuzz_stacktrace();
	fuzz_emu_stop_crash("stack chk fail report\n");
	vm_stop(RUN_STATE_RESTORE_VM);
	return EXCP_HALTED;
}

static int idle_crash(void) {
	fuzz_stacktrace();
	fuzz_emu_stop_crash("idle report\n");
	vm_stop(RUN_STATE_RESTORE_VM);
	return EXCP_HALTED;
}

static int die_crash(void) {
	fuzz_stacktrace();
	fuzz_emu_stop_crash("die report\n");
	vm_stop(RUN_STATE_RESTORE_VM);
	return EXCP_HALTED;
}

static int abort_crash(void) {
	fuzz_stacktrace();
	fuzz_emu_stop_crash("abort report\n");
	vm_stop(RUN_STATE_RESTORE_VM);
	return EXCP_HALTED;
}

static int skip(void) {
	fuzz_emu_stop_unhealthy();
	vm_stop(RUN_STATE_RESTORE_VM);
	return EXCP_HALTED;
}

void apply_breakpoints_linux() {
	add_breakpoint(
		sym_to_addr2("libasan.so",
			    "__asan::ScopedInErrorReport::~ScopedInErrorReport"),
		libasan_crash);
	add_breakpoint(sym_to_addr2("vmlinux", "asm_exc_page_fault"), page_fault_crash);
	add_breakpoint(sym_to_addr2("vmlinux", "__stack_chk_fail"), stack_chk_fail_crash);
	add_breakpoint(sym_to_addr2("vmlinux", "do_idle"), idle_crash);
	add_breakpoint(sym_to_addr2("vmlinux", "die"), die_crash);
	add_breakpoint(sym_to_addr2("libc.so.6", "abort@@GLIBC_2.17"), abort_crash);
}

void hp_vcpu_syscall(int64_t num, uint64_t a1, uint64_t a2, uint64_t a3,
		     uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
		     uint64_t a8) {
	switch (num) {
	case 93: /* exit */
	case 94: /* exit_group */
		fuzz_emu_stop_crash("exit syscall");
	case 129: /* kill */
	case 130: /* tkill */
		if (a1 == 6) { /* sigabrt */
			fuzz_emu_stop_crash("kill syscall");
		}
		break;
	}
}