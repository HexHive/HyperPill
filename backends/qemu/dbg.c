#include "qemu.h"

void icp_init_gdb(void) {
	QEMU_CPU(0)->fuzzdebug_gdb = getenv("GDB");
}

bool is_gdbstub_enabled() {
	return QEMU_CPU(0)->fuzzdebug_gdb;
}

void hp_gdbstub_debug_loop(void) {
	gdbserver_start("tcp::1234");
}