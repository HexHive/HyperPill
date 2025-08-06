#include "bochs.h"
#include "cpu/cpu.h"

BOCHSAPI bx_debug_t bx_dbg;

void icp_init_gdb(void) {
	if (getenv("GDB")) {
		bx_dbg.gdbstub_enabled = 1;
	}
	BX_CPU(id)->fuzzdebug_gdb = getenv("GDB");
}

bool is_gdbstub_enabled() {
	return BX_CPU(id)->fuzzdebug_gdb;
}
