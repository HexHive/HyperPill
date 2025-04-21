#include "qemu.h"

void dump_regs() {
    cpu_dump_state(QEMU_CPU(0), NULL, CPU_DUMP_FPU);
	fflush(stdout);
	fflush(stderr);
}

uint64_t cpu0_get_pc(void) {
    return (&(ARM_CPU(QEMU_CPU(0)))->env)->pc;
}

void cpu0_set_pc(uint64_t pc) {
    (&(ARM_CPU(QEMU_CPU(0)))->env)->pc = pc;
}

void save_cpu() {}

void cpu0_run_loop() {
	// FIXME : BX_CPU(id)->cpu_loop() is probably blocking, which is not the case
	// for us with qemu_start_vm();
	// TODO : block on a barrier or something
	qemu_wait_until_stop();
}