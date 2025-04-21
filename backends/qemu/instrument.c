#include "fuzz.h"
#include <unordered_set>

#include <cstdio>
#include <cstdint>

/* File of PCs covered */
FILE *file_pcs_covered = NULL;
std::unordered_set<uint64_t> pcs_covered;

extern "C"
void write_pcs_execution(uint64_t pc, uint64_t pc_last) {
    /* Init PC file */
    if (file_pcs_covered == NULL) {
        file_pcs_covered = fopen("pcs_covered.txt", "w");
        if (file_pcs_covered == NULL) {
            perror("Could not open coverage file\n");
            exit(1);
        }
    }

    size_t num_instr = ((pc_last - pc) / 4) + 1; // We assume 32 bit ARM instructions

    for(size_t i = 0; i < num_instr; i++) {
        uint64_t curr_pc = pc + (i*4);
        if (pcs_covered.find(curr_pc) == pcs_covered.end()) {
            pcs_covered.insert(curr_pc);
            fprintf(file_pcs_covered, "%016lX\n", curr_pc); // We assume 32 bit ARM instructions
        }
    }

    fflush(file_pcs_covered);
}

extern "C"
void qemu_ctrl_flow_insn(uint64_t branch_pc, uint64_t new_pc) {
    add_edge(branch_pc, new_pc);
    add_stacktrace(branch_pc, new_pc);
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