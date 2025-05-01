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
	return EXCP_DEBUG;
}

static int page_fault_crash(void) {
	printf("page fault");
	// fuzz_emu_stop_crash("page fault");
	return 0;
}

void apply_breakpoints_linux() {
	add_breakpoint(
		sym_to_addr2("libasan.so",
			    "__asan::ScopedInErrorReport::~ScopedInErrorReport"),
		libasan_crash);
	add_breakpoint(sym_to_addr2("vmlinux", "asm_exc_page_fault"), page_fault_crash);
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