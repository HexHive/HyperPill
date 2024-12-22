#include "fuzz.h"

void dump_regs() {
    __dump_regs();
	fflush(stdout);
	fflush(stderr);
}

uint64_t cpu0_get_pc(void) {
    return __cpu0_get_pc();
}

void cpu0_set_pc(uint64_t pc) {
    return __cpu0_set_pc(pc);
}