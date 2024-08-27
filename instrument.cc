#include "bochs.h"
#include "fuzz.h"
#include "cpu/cpu.h"

void bx_instr_lin_access(unsigned cpu, bx_address lin, bx_address phy,
                         unsigned len, unsigned memtype, unsigned rw, void *dataptr) {
  fuzz_hook_memory_access(phy, len, memtype, rw, dataptr);
}
void bx_instr_phy_access(unsigned cpu, bx_address phy, unsigned len,
                         unsigned memtype, unsigned rw, void* dataptr) {
  fuzz_hook_memory_access(phy, len, memtype, rw, dataptr);
}

void bx_instr_init_env(void) {}
void bx_instr_exit_env(void) {}

void bx_instr_initialize(unsigned cpu) {}
void bx_instr_exit(unsigned cpu) {}
void bx_instr_reset(unsigned cpu, unsigned type) {}
void bx_instr_hlt(unsigned cpu) {fuzz_hook_hlt();}
void bx_instr_mwait(unsigned cpu, bx_phy_address addr, unsigned len, Bit32u flags) {}

void bx_instr_debug_promt() {}
void bx_instr_debug_cmd(const char *cmd) {}

void bx_instr_cnear_branch_taken(unsigned cpu, bx_address branch_eip, bx_address new_eip) {
    fuzz_instr_cnear_branch_taken(branch_eip, new_eip);
}
void bx_instr_cnear_branch_not_taken(unsigned cpu, bx_address branch_eip) {
    fuzz_instr_cnear_branch_not_taken(branch_eip);
}
void bx_instr_ucnear_branch(unsigned cpu, unsigned what, bx_address branch_eip, bx_address new_eip) {
    fuzz_instr_ucnear_branch(what, branch_eip, new_eip);
}
void bx_instr_far_branch(unsigned cpu, unsigned what, Bit16u prev_cs, bx_address prev_eip, Bit16u new_cs, bx_address new_eip) {
    fuzz_instr_far_branch(what, prev_cs, prev_eip, new_cs, new_eip);
}

void bx_instr_opcode(unsigned cpu, bxInstruction_c *i, const Bit8u *opcode, unsigned len, bool is32, bool is64) {}

void bx_instr_interrupt(unsigned cpu, unsigned vector) { fuzz_instr_interrupt(cpu, vector);}

void bx_instr_exception(unsigned cpu, unsigned vector, unsigned error_code) {
    fuzz_hook_exception(vector, error_code);
}
void bx_instr_hwinterrupt(unsigned cpu, unsigned vector, Bit16u cs, bx_address eip) {}

void bx_instr_tlb_cntrl(unsigned cpu, unsigned what, bx_phy_address new_cr3) {}
void bx_instr_clflush(unsigned cpu, bx_address laddr, bx_phy_address paddr) {}
void bx_instr_cache_cntrl(unsigned cpu, unsigned what) {}
void bx_instr_prefetch_hint(unsigned cpu, unsigned what, unsigned seg, bx_address offset) {}

void bx_instr_before_execution(unsigned cpu, bxInstruction_c *i) {
    fuzz_instr_before_execution(i);
}
void bx_instr_after_execution(unsigned cpu, bxInstruction_c *i) {
    fuzz_instr_after_execution(i);
}
void bx_instr_repeat_iteration(unsigned cpu, bxInstruction_c *i) {}

void bx_instr_inp(Bit16u addr, unsigned len) {}
void bx_instr_inp2(Bit16u addr, unsigned len, unsigned val) {}
void bx_instr_outp(Bit16u addr, unsigned len, unsigned val) {}


void bx_instr_wrmsr(unsigned cpu, unsigned addr, Bit64u value) {}

void bx_instr_vmexit(unsigned cpu, Bit32u reason, Bit64u qualification) {}
