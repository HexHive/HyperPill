#include "qemu.h"

extern CPUState qemu_cpu;

void el_change_fn(ARMCPU *cpu, void *opaque) {
}

/* Copied from QEMU 8.2.0, target/arm/tcg/helper-a64.c */
int el_from_spsr(uint32_t spsr)
{
    /* Return the exception level that this SPSR is requesting a return to,
     * or -1 if it is invalid (an illegal return)
     */
    if (spsr & PSTATE_nRW) {
        switch (spsr & CPSR_M) {
        case ARM_CPU_MODE_USR:
            return 0;
        case ARM_CPU_MODE_HYP:
            return 2;
        case ARM_CPU_MODE_FIQ:
        case ARM_CPU_MODE_IRQ:
        case ARM_CPU_MODE_SVC:
        case ARM_CPU_MODE_ABT:
        case ARM_CPU_MODE_UND:
        case ARM_CPU_MODE_SYS:
            return 1;
        case ARM_CPU_MODE_MON:
            /* Returning to Mon from AArch64 is never possible,
             * so this is an illegal return.
             */
        default:
            return -1;
        }
    } else {
        if (extract32(spsr, 1, 1)) {
            /* Return with reserved M[1] bit set */
            return -1;
        }
        if (extract32(spsr, 0, 4) == 1) {
            /* return to EL0 with M[0] bit set */
            return -1;
        }
        return extract32(spsr, 2, 2);
    }
}



void pre_el_change_fn(ARMCPU *cpu, void *opaque) {
	CPUARMState *env = &cpu->env;
    CPUState *cs = env_cpu(env);

    unsigned int cur_el = arm_current_el(env);

    /* If we exit the hypervisor... 
     *
     * NOTE: checking cur_el = 2, new_el = 1 should only work on hardware
     * providing ARM VHE and hypervisor making use of VHE mode.
     * Without ARM VHE, a hosted hypervisor would work in split mode, with a 
     * stub that catches all traps to EL2 and redirects control flow to EL1
     * where the hypervisor actually sits. In that case, we would need more
     * checks to differentiate whether we are returning control to the
     * guest OS or the host OS/hypervisor running in EL1.
     */
    if (cur_el == 2) {
        unsigned int spsr_idx = aarch64_banked_spsr_index(cur_el);
        uint32_t spsr = env->banked_spsr[spsr_idx];
        unsigned int new_el = el_from_spsr(spsr);
    
        if (new_el == 1) {
            fuzz_hook_back_to_el1_kernel();
        }
    }
}

void before_exec_tb_fn(int cpu_index, TranslationBlock *tb) {
    if(tb == NULL || QEMU_CPU(0)->cpu_index != cpu_index)
        return;

    qemu_tb_before_execution(NULL);
}

void after_exec_tb_fn(int cpu_index, TranslationBlock *tb) {
    static uint64_t prev_pc = 0;

    if(tb == NULL || QEMU_CPU(0)->cpu_index != cpu_index)
        return;

    // printf("TB executed: cpu_index=%d pc=0x%"PRIxPTR" pc_end=0x%"PRIxPTR "\n",
    //    cpu_index, tb->pc, tb->pc_last);

    if (prev_pc == 0) {
        prev_pc = tb->pc;
        return;
    }

    qemu_ctrl_flow_insn(prev_pc, tb->pc);
    prev_pc = tb->pc;
    qemu_tb_after_execution(NULL);
    write_pcs_execution(tb->pc, tb->pc_last);
}


void init_qemu(int argc, char **argv) {
    qemu_mutex_init(&barrier_mutex);
    qemu_cond_init(&barrier_cond);

    /* Save PC address pre VMENTER before restarting the VM */
    save_pre_hyp_pc();
}

void icp_init_backend() {
	int qemu_argc = 9;
	char *qemu_argv[] = {
		"qemu-system-aarch64",
		"-smp", "1",
		"-m", "8192", // TODO: we assume at most 8G?
		"-cpu", "max",
		"-M", "virt,virtualization=on",
		NULL
	};
    qemu_init(qemu_argc, qemu_argv);
    qemu_cpu = *(first_cpu);
    printf("CPU0 is at index : %d\n", QEMU_CPU(0)->cpu_index);

    arm_register_el_change_hook(ARM_CPU(QEMU_CPU(0)), el_change_fn, NULL);
    arm_register_pre_el_change_hook(ARM_CPU(QEMU_CPU(0)), pre_el_change_fn, NULL);
    register_exec_tb_cb(before_exec_tb_fn, after_exec_tb_fn);
}