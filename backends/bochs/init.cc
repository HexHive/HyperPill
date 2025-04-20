#include "bochs.h"
#include "cpu/cpu.h"
#include <stdio.h>
#include <stdlib.h>

extern BX_CPU_C bx_cpu;
extern void icp_init_params();
extern void init_cpu();
extern void bx_init_pc_system();

void icp_init_backend() {
	/* Bochs-specific initialization. (e.g. CPU version/features). */
	if (getenv("GDB")) {
		bx_dbg.gdbstub_enabled = 1;
	}
	icp_init_params();
	init_cpu();
	bx_init_pc_system();

	BX_CPU(id)->fuzzdebug_gdb = getenv("GDB");
}