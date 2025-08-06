#include "qemu.h"

void icp_init_gdb(void) {

}

bool is_gdbstub_enabled() {
	return QEMU_CPU(0)->fuzzdebug_gdb;
}