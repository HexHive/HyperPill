#include "qemu.h"

void icp_init_regs(const char* filename) {
    Error *err = NULL;
    hp_load_devices_state(filename, &err);
}

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

size_t init_random_register_data_len(void) {
	assert(0);
}

bool cpu0_get_user_pl(void) {
	assert(0);
}

void save_cpu() {
	shadow_qemu_cpu = qemu_cpu;
}

void restore_cpu() {
	qemu_cpu = shadow_qemu_cpu;
}

void cpu0_set_general_purpose_reg64(unsigned reg, uint64_t value) {
	 assert(0);
}