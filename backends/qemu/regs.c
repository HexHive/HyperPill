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
    return arm_current_el(&(ARM_CPU(QEMU_CPU(0))->env)) == 0;
}

void save_cpu() {
    assert(!runstate_is_running());
}

void restore_cpu() {
    if (!qemu_mutex_iothread_locked())
        qemu_mutex_lock_iothread();
    int saved_vm_running = runstate_is_running();
    if (saved_vm_running) {
        vm_stop(RUN_STATE_RESTORE_VM);
    }
	char *regs_path = getenv("ICP_REGS_PATH");
    icp_init_regs(regs_path);
}

void cpu0_set_general_purpose_reg64(unsigned reg, uint64_t value) {
    assert(reg < 32);
    (ARM_CPU(QEMU_CPU(0))->env).xregs[reg] = value;
}

uint64_t cpu0_get_general_purpose_reg64(unsigned reg) {
    assert(reg < 32);
    return (ARM_CPU(QEMU_CPU(0))->env).xregs[reg];
}

void aarch64_set_esr_el2_for_hvc() {
    CPUARMState *env = &(ARM_CPU(QEMU_CPU(0))->env);
    env->cp15.esr_el[2] =
          (0x16 << 26) // HVC_AA64
        |    (1 << 25) // 32 bit instruction trapped
        ;
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

    CPUARMState *env = &(ARM_CPU(QEMU_CPU(0))->env);
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
    CPUARMState *env = &(ARM_CPU(QEMU_CPU(0))->env);
    env->cp15.far_el[2] = far;
}

uint64_t aarch64_get_far_el2(void) {
    CPUARMState *env = &(ARM_CPU(QEMU_CPU(0))->env);
    return env->cp15.far_el[2];
}

void aarch64_set_hpfar_el2(uint64_t addr) {
    CPUARMState *env = &(ARM_CPU(QEMU_CPU(0))->env);
    env->cp15.hpfar_el2 = extract64(addr, 12, 47) << 4;
}

uint64_t aarch64_get_hpfar_el2(void) {
    CPUARMState *env = &(ARM_CPU(QEMU_CPU(0))->env);
    return env->cp15.hpfar_el2;
}
