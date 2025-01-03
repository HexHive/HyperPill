#include "fuzz.h"

extern "C"
void qemu_ctrl_flow_insn(uint64_t branch_pc, uint64_t new_pc) {
    add_edge(branch_pc, new_pc);
}

extern "C"
void qemu_tb_hlt(unsigned cpu) {
    fuzz_hook_hlt();
}

extern "C"
void qemu_tb_exception(unsigned cpu, unsigned vector, unsigned error_code) {
    fuzz_hook_exception(vector, error_code);
}

extern "C"
void qemu_tb_interrupt(unsigned cpu, unsigned vector) {
    fuzz_instr_interrupt(cpu, vector);
}

extern "C"
void qemu_tb_before_execution(hp_instruction *i) {
    // this is an approximation
    fuzz_instr_before_execution(i);
}

extern "C"
void qemu_tb_after_execution(hp_instruction *i) {
    // this is an approximation
    fuzz_instr_after_execution(i);
}