#include "qemu_c.h"
#include "qemuapi.h"

/* previous PC before entering hypervisor */
static uint64_t pre_hyp_pc = 0;

QemuMutex barrier_mutex;
QemuCond barrier_cond;

/* The CPU handling the VM EXIT */
static CPUState *cpu0 = NULL;

void qemu_wait_until_stop() {
    qemu_mutex_lock(&barrier_mutex);

    while(__cpu0_get_fuzz_executing_input()) {
        qemu_cond_wait(&barrier_cond, &barrier_mutex);
    }

    qemu_mutex_unlock(&barrier_mutex);
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

static void pre_el_change_fn(ARMCPU *cpu, void *opaque) {
	CPUARMState *env = &cpu->env;
    CPUState *cs = env_cpu(env);

    unsigned int cur_el = arm_current_el(env);

    /* If we exit the hypervisor */
    if (cur_el == 2) {
        unsigned int spsr_idx = aarch64_banked_spsr_index(cur_el);
        uint32_t spsr = env->banked_spsr[spsr_idx];
        unsigned int new_el = el_from_spsr(spsr);
    
        if (new_el == 1) {
            fuzz_hook_back_to_el1_kernel();
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

// for mmio (linux kernel)
//
// kvm_arch_vcpu_ioctl_run()
//   -> kvm_hanlde_mmio_return() if run->exit_reason == KVM_EXIT_MMIO
//   -> while (ret > 0)
//     -> ret = kvm_arm_vcpu_enter_exit()
//     | -> __kvm_vcpu_run()
//     | | -> __kvm_vcpu_run_vhe()
//     | | | -> do { exit_code = __guest_enter() }
//     | | | | -> el1_sync                                                // where we take the snapshot
//     | | | | | -> el1_trap
//     | | | | | -> return exit_code=ARM_EXCEPTION_TRAP
//     | | | | -> return exit_code=ARM_EXCEPTION_TRAP
//     | | | -> while(fixup_guest_exit())
//     | | | | -> kvm_hyp_handle_exit()
//     | | | | | -> kvm_hyp_handle_dabt_low()
//     | | | | |   -> __populate_fault_info()
//     | | | | |     -> __get_fault_info()                                // need to set up FAR_EL2 and HPFAR_EL2
//     | | | | -> return false
//     | | | -> return exit_code
//     | | -> return exit_code
//     | -> return exit_code
//     -> handle_exit()
//       -> handle_trap_exceptions()
//         -> kvm_handle_guest_abort()
//           -> fault_status = kvm_vcpu_trap_get_fault_type()             // need to change ESR_EL2.FSC
//           -> fault_ipa = kvm_vcpu_get_fault_ipa()                      // should be valid
//           -> write_fault = kvm_is_write_fault(vcpu)
//             -> if (kvm_vcpu_abt_iss1tw()) { goto ...; }                // ESR_EL2.S1PTW should be 0
//             -> if (kvm_vcpu_trap_is_iabt()) { goto ...; }              // ESR_EL2.FSC should be data abort
//             -> return kvm_vcpu_dabt_iswrite(vcpu);                     // ESR_EL2.WNR for read or write
//           -> if (kvm_is_error_hva(hva) || (write_fault && !writable))  // should be true
//             -> if (kvm_vcpu_abt_iss1tw()) { goto ...; }                // ESR_EL2.S1PTW should be 0
//             -> if (kvm_vcpu_trap_is_iabt()) { goto ...; }              // ESR_EL2.FSC should be data abort
//             -> if (kvm_vcpu_dabt_is_cm()) { goto ...}                  // ESL_EL2.CM should be 0
//             -> fault_ipa |= kvm_vcpu_get_hfar(vcpu) & ((1 << 12) - 1)  // FAR_EL2 only needs the low 12 bit
//             -> io_mem_abort()
//               -> if (!kvm_vcpu_dabt_isvalid(vcpu)) { ... }             // ESR_EL2.ISV should be 1
//               -> is_write = kvm_vcpu_dabt_iswrite()                    // ESR_EL2.WNR for read or write
//               -> len = kvm_vcpu_dabt_get_as()                          // ESR_EL2.SAS for size
//               -> rt = kvm_vcpu_dabt_get_rd()                           // ESR_EL2.SRT for register operand


// in QEMU
// break at arm_cpu_do_interrupt_aarch64()
// with conditions: cs->exception_index == EXCP_DATA_ABORT && env->cp15.hpfar_el2 == (mmio_base >> 8)

#define   il  1
#define   isv 1
#define   sse 0
#define    sf 0
#define    ar 0
#define  vncr 0
#define   set 0
#define   fnv 0
#define    ea 0
#define    cm 0
#define s1ptw 0
#define  fsc  6

void aarch64_set_esr_el2_for_data_abort(int sas, int srt, int write_or_read) {
    int wnr = write_or_read;

    CPUARMState *env = &(ARM_CPU(cpu0))->env;
    env->cp15.esr_el[2] =
         (0x24 << 26) // data abort from a lower exception level
        |  (il << 25) // 1, 32-bit instruction trapped
        | (isv << 24) // 1, have a valid instruction syndrome
        | (sas << 22) // ?, 0 for byte, 1 for harfword, 2 for word, 3 for doubleword
        | (sse << 21) // 0, sign-extension not required
        | (srt << 16) // ?, xregs[srt] contains the value of mmio_write
        |  (sf << 15) // 0, register width, 0 for 32 bit, 1 for 64 bit (might be 1? not sure)
        |  (ar << 14) // 0, not have acquire/release semantics
        |(vncr << 13) // 0, not generated by the use of VNCR_EL2
        | (set << 11) // 0, not related to mmio data abort
        | (fnv << 10) // 0, far is valid
        |  (ea <<  9) // 0, not related to mmio data abort
        |  (cm <<  8) // 0, not cache maintenance
        |(s1ptw<<  7) // 0, not on a stage 2 translation for a stage 1 translation table walk
        | (wnr <<  6) // ?, 0 for read and 1 for write
        | (fsc <<  0) // 6, traslation fault, level 2
        ;
}

void aarch64_set_far_el2(uint64_t far) {
    CPUARMState *env = &(ARM_CPU(cpu0))->env;
    env->cp15.far_el[2] = far;
}

uint64_t aarch64_get_far_el2(void) {
    CPUARMState *env = &(ARM_CPU(cpu0))->env;
    return env->cp15.far_el[2];
}

void aarch64_set_hpfar_el2(uint64_t addr) {
    CPUARMState *env = &(ARM_CPU(cpu0))->env;
    env->cp15.hpfar_el2 = extract64(addr, 12, 47) << 4;
}

uint64_t aarch64_get_hpfar_el2(void) {
    CPUARMState *env = &(ARM_CPU(cpu0))->env;
    return env->cp15.hpfar_el2;
}

void aarch64_set_xreg(uint64_t index, uint64_t value) {
    assert(index < 32);
    CPUARMState *env = &(ARM_CPU(cpu0))->env;
    env->xregs[index] = value;
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

void before_exec_tb_fn(int cpu_index, TranslationBlock *tb) {
    if(tb == NULL || cpu0->cpu_index != cpu_index)
        return;

    qemu_tb_before_execution(NULL);
}

void after_exec_tb_fn(int cpu_index, TranslationBlock *tb) {
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
    qemu_tb_after_execution(NULL);
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
    register_exec_tb_cb(before_exec_tb_fn, after_exec_tb_fn);

    printf("Enters Hypervisor at address : 0x%"PRIxPTR "\n", (&(ARM_CPU(cpu0))->env)->pc);
    printf("Last PC before entering Hypervisor : 0x%"PRIxPTR "\n", (&(ARM_CPU(cpu0))->env)->elr_el[2]);
}

// breakpoints.c
#define GDB_BREAKPOINT_HW        1

bool __add_breakpoint(vaddr addr, int (*h)(void)) {
    return gdb_breakpoint_insert(cpu0, GDB_BREAKPOINT_HW, addr, 0x1000, h);
}

// control.c
bool __cpu0_get_fuzztrace(void) {
    return cpu0->fuzztrace;
}

void __cpu0_set_fuzztrace(bool fuzztrace) {
    cpu0->fuzztrace = fuzztrace;
}

static void qemu_signal_stop() {
    qemu_mutex_lock(&barrier_mutex);
    qemu_cond_signal(&barrier_cond);
    qemu_mutex_unlock(&barrier_mutex);
}

static void qemu_start_vm() {
    vm_start();
    if (qemu_mutex_iothread_locked()) {
        qemu_mutex_unlock_iothread();
    }
}

static void qemu_set_running() {
    qemu_mutex_lock(&barrier_mutex);
	qemu_start_vm();
    qemu_mutex_unlock(&barrier_mutex);
}

bool __cpu0_get_fuzz_executing_input(void) {
    return cpu0->fuzz_executing_input;
}

void __cpu0_set_fuzz_executing_input(bool fuzzing) {
    cpu0->fuzz_executing_input = fuzzing;
    if (!fuzzing) {
        qemu_signal_stop();
    } else {
        qemu_set_running();
    }
}

// mem.c
void __cpu0_mem_write_physical_page(hwaddr addr, size_t len, void *buf) {
    cpu_physical_memory_write(addr, buf, len);
}

void __cpu0_mem_read_physical_page(hwaddr addr, size_t len, void *buf) {
    cpu_physical_memory_read(addr, buf, len);
}

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

