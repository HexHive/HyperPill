#include "fuzz.h"

extern "C"
void qemu_ctrl_flow_insn(uint64_t branch_pc, uint64_t new_pc) {
    add_edge(branch_pc, new_pc);
}
