#include "fuzz.h"
#include "qemu_c.h"

void dump_regs() {
    cpu_dump_state(cpu0, NULL, CPU_DUMP_FPU);
	fflush(stdout);
	fflush(stderr);
}

uint64_t cpu0_get_pc(void) {
    return __cpu0_get_pc();
}

void cpu0_set_pc(uint64_t pc) {
    return __cpu0_set_pc(pc);
}

void save_cpu()

void cpu0_run_loop() {
	// FIXME : BX_CPU(id)->cpu_loop() is probably blocking, which is not the case
	// for us with qemu_start_vm();
	// TODO : block on a barrier or something
	qemu_wait_until_stop();
}