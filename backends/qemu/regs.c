#include "qemu.h"

void icp_init_regs(const char* filename) {
    Error *err = NULL;
    hp_load_devices_state(filename, &err);
}

void dump_regs() {
    CPUARMState *env = &(ARM_CPU(QEMU_CPU(0))->env);
	printf(" PC=%016" PRIx64 " ", env->pc);
    for (int i = 0; i < 32; i++) {
        if (i == 31) {
            printf(" SP=%016" PRIx64 "\n", env->xregs[i]);
        } else {
            printf("X%02d=%016" PRIx64 "%s", i, env->xregs[i], (i + 2) % 3 ? " " : "\n");
        }
    }
	fflush(stdout);
	fflush(stderr);
}

uint64_t cpu0_get_pc(void) {
    return (ARM_CPU(QEMU_CPU(0))->env).pc;
}

void cpu0_set_pc(uint64_t pc) {
    (ARM_CPU(QEMU_CPU(0))->env).pc = pc;
}

size_t init_random_register_data_len(void) {
	// 31 64-bit generial-prpose registers, X0-X30
	return 31 * 8;
}

bool cpu0_get_user_pl(void) {
    return arm_current_el(ARM_CPU(QEMU_CPU(0))->env) == 0;
}

void save_cpu() {
	shadow_qemu_cpu = *(first_cpu);
}

void restore_cpu() {
	*(first_cpu) = shadow_qemu_cpu;
}

void cpu0_set_general_purpose_reg64(unsigned reg, uint64_t value) {
    assert(reg < 31);
    (ARM_CPU(QEMU_CPU(0))->env).xregs[reg] = value;
}

void cpu0_get_general_purpose_reg64(unsigned reg) {
    assert(reg < 31);
    return (ARM_CPU(QEMU_CPU(0))->env).xregs[reg];
}