#include "qemu.h"

void el_change_fn(ARMCPU *cpu, void *opaque) {
	CPUARMState *env = &cpu->env;
    CPUState *cs = env_cpu(env);
    // TODO : leaving it here in case we need it
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
    qemu_init(argc, argv);
    //hp_qemu_plugin_load();

    qemu_mutex_init(&barrier_mutex);
    qemu_cond_init(&barrier_cond);

    CPUState *cpu;
    CPU_FOREACH(cpu) {
        arm_register_el_change_hook(ARM_CPU(cpu), el_change_fn, NULL);
        arm_register_pre_el_change_hook(ARM_CPU(cpu), pre_el_change_fn, NULL);
    }

    CPU_FOREACH(cpu) {
        CPUARMState *env = &(ARM_CPU(cpu))->env;
        if (env->xregs[0] == 0xdeadbeef) {
            cpu0 = *cpu;
            break;
        }
    }

    printf("CPU0 is at index : %d\n", QEMU_CPU(0)->cpu_index);

    /* Save PC address pre VMENTER before restarting the VM */
    save_pre_hyp_pc();

    /* Register TB execution callback */
    register_exec_tb_cb(before_exec_tb_fn, after_exec_tb_fn);

    printf("Enters Hypervisor at address : 0x%"PRIxPTR "\n", (&(ARM_CPU(QEMU_CPU(0)))->env)->pc);
    printf("Last PC before entering Hypervisor : 0x%"PRIxPTR "\n", (&(ARM_CPU(QEMU_CPU(0)))->env)->elr_el[2]);
}

void icp_init_backend() {
	int qemu_argc = 20;
	char *qemu_argv[] = {
		"qemu-system-aarch64",
		"-smp", "1",
		"-m", "8192",
		"-cpu", "max",
		"-M", "virt,virtualization=on",
		NULL
	};
	init_qemu(qemu_argc, qemu_argv);
}