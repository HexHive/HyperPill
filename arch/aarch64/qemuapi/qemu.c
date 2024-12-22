#include "qemu_c.h"
#include "qemuapi.h"

/* previous PC before entering hypervisor */
static uint64_t pre_hyp_pc = 0;

static bool fuzztrace_input = false;
QemuMutex barrier_mutex;
QemuCond barrier_cond;

/* The CPU handling the VM EXIT */
static CPUState *cpu0 = NULL;

/* Forward declaration */
bool cpu0_get_fuzz_executing_input(void);

void qemu_wait_until_stop() {
    qemu_mutex_lock(&barrier_mutex);

    while(cpu0_get_fuzz_executing_input()) {
        qemu_cond_wait(&barrier_cond, &barrier_mutex);
    }

    qemu_mutex_unlock(&barrier_mutex);
}

void qemu_signal_stop() {
    qemu_mutex_lock(&barrier_mutex);
    fuzztrace_input = false;
    qemu_cond_signal(&barrier_cond);
    qemu_mutex_unlock(&barrier_mutex);
}

void qemu_set_running() {
    qemu_mutex_lock(&barrier_mutex);
    fuzztrace_input = true;
	qemu_start_vm();
    qemu_mutex_unlock(&barrier_mutex);
}

bool qemu_is_running() {
    return fuzztrace_input;
}

/* Copied from QEMU 8.2.0, target/arm/tcg/helper-a64.c */
static int el_from_spsr(uint32_t spsr)
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

/* Forward declaration */
void fuzz_emu_stop_normal();

static void pre_el_change_fn(ARMCPU *cpu, void *opaque) {
	CPUARMState *env = &cpu->env;
    CPUState *cs = env_cpu(env);

    unsigned int cur_el = arm_current_el(env);

    /* If we exit the hypervisor */
    if (cur_el == 2) {
        unsigned int spsr_idx = aarch64_banked_spsr_index(cur_el);
        uint32_t spsr = env->banked_spsr[spsr_idx];
        unsigned int new_el = el_from_spsr(spsr);
    
        printf("Detecting EL2 -> EL%u\n", new_el);
        if (new_el == 1) {
            if (pre_hyp_pc == env->elr_el[2]) {
                printf("Detecting an ERET to guest VM\n");
                fuzz_emu_stop_normal();
            }
        }
    }
}

static void el_change_fn(ARMCPU *cpu, void *opaque) {
	CPUARMState *env = &cpu->env;
    CPUState *cs = env_cpu(env);

    // TODO : leaving it here in case we need it
}

void aarch64_set_xregs(uint64_t xregs[32]) {
    CPUARMState *env = &(ARM_CPU(cpu0))->env;
    memcpy(env->xregs, xregs, sizeof(xregs[32]));
}

void aarch64_set_esr_el2(aa64_syndrom syndrom) {
    CPUARMState *env = &(ARM_CPU(cpu0))->env;
    uint8_t excp_code = excp_codes[syndrom];
    env->cp15.esr_el[2] |= (uint64_t)excp_code << 26; // TODO : add IL and ISS fields
}

void qemu_start_vm() {
    vm_start();
    qemu_mutex_unlock_iothread();
}

bool qemu_reload_vm(char *snapshot_tag) {
    Error *err;

    if (!qemu_mutex_iothread_locked())
        qemu_mutex_lock_iothread();

    vm_stop(RUN_STATE_RESTORE_VM);

    bool success = load_snapshot(snapshot_tag, NULL, false, NULL, &err);
    if(!success) {
        printf("Error loading snapshot\n");
        error_report_err(err);
    }

    return success;
}

void save_pre_hyp_pc() {
    CPUARMState *env = &(ARM_CPU(cpu0))->env;
    pre_hyp_pc = env->elr_el[2];
}

void exec_tb_fn(int cpu_index, TranslationBlock *tb) {
    static uint64_t prev_pc = 0;

    if(tb == NULL || cpu0->cpu_index != cpu_index)
        return;

    // printf("TB executed: cpu_index=%d pc=0x%"PRIxPTR" pc_end=0x%"PRIxPTR "\n",
    //    cpu_index, tb->pc, tb->pc_last);

    if (prev_pc == 0) {
        prev_pc = tb->pc;
        return;
    }

    qemu_ctrl_flow_insn(prev_pc, tb->pc);
    prev_pc = tb->pc;
}

void init_qemu(int argc, char **argv, char *snapshot_tag) {
    qemu_init(argc, argv);

    qemu_mutex_init(&barrier_mutex);
    qemu_cond_init(&barrier_cond);

    CPUState *cpu;
    CPU_FOREACH(cpu) {
        arm_register_el_change_hook(ARM_CPU(cpu), el_change_fn, NULL);
        arm_register_pre_el_change_hook(ARM_CPU(cpu), pre_el_change_fn, NULL);
    }

    printf(".loading vm snapshot\n");
    if (!qemu_reload_vm(snapshot_tag)) {
        printf("Fail to load snapshot %s\n", snapshot_tag);
    }

    CPU_FOREACH(cpu) {
        CPUARMState *env = &(ARM_CPU(cpu))->env;
        if (env->xregs[0] == 0xdeadbeef) {
            cpu0 = cpu;
            break;
        }
    }

    assert(cpu0 != NULL);

    printf("CPU0 is at index : %d\n", cpu0->cpu_index);

    /* Save PC address pre VMENTER before restarting the VM */
    save_pre_hyp_pc();

    /* Register TB execution callback */
    register_exec_tb_cb(exec_tb_fn);

    printf("Enters Hypervisor at address : 0x%"PRIxPTR "\n", (&(ARM_CPU(cpu0))->env)->pc);
    printf("Last PC before entering Hypervisor : 0x%"PRIxPTR "\n", (&(ARM_CPU(cpu0))->env)->elr_el[2]);
}

// mem.c
int __cpu0_memory_rw_debug(vaddr addr, void *ptr, size_t len, bool is_write) {
    return cpu_memory_rw_debug(cpu0, addr, ptr, len, is_write);
}

// regs.c
void __dump_regs(void) {
    cpu_dump_state(cpu0, NULL, CPU_DUMP_FPU);
}

uint64_t __cpu0_get_pc(void) {
    return (&(ARM_CPU(cpu0))->env)->pc;
}

void __cpu0_set_pc(uint64_t pc) {
    (&(ARM_CPU(cpu0))->env)->pc = pc;
}
