#include "qemu_c.h"
#include "qemuapi.h"

void aarch64_set_xregs(uint64_t xregs[32]) {
    CPUState *cpu;
    CPU_FOREACH(cpu) {
        CPUARMState *env = &(ARM_CPU(cpu))->env;
        if (env->xregs[0] == 0xdeadbeef) { // FIXME : here we are assuming the CPU is stopped right after a VM_EXIT. CHANGE THAT !
            memcpy(env->xregs, xregs, sizeof(xregs[32]));
            break;
        }
    }
}

void aarch64_set_esr_el2(aa64_syndrom syndrom) {
    // TODO
    CPUState *cpu;
    CPU_FOREACH(cpu) {
        CPUARMState *env = &(ARM_CPU(cpu))->env;
        if (env->xregs[0] == 0xdeadbeef) { // FIXME : here we are assuming the CPU is stopped right after a VM_EXIT. CHANGE THAT !
            uint8_t excp_code = excp_codes[syndrom];
            env->cp15.esr_el[2] |= (uint64_t)excp_code << 26; // TODO : add IL and ISS fields
            break;
        }
    }
}

void qemu_start_vm() {
    vm_start();
}

bool qemu_reload_vm(char *tag) {
    Error *err;

    vm_stop(RUN_STATE_RESTORE_VM);

    bool success = load_snapshot(tag, NULL, false, NULL, &err);
    if(!success) {
        printf("Error loading snapshot\n");
        error_report_err(err);
    } else {
        printf("Successful snapshot load\n");
    }

    return success;
}

void init_qemu(int argc, char **argv) {
    qemu_init(argc, argv);
    
    char *snapshot_tag = getenv("SNAPSHOT_BASE");
    if (snapshot_tag != NULL) {
        qemu_reload_vm(snapshot_tag);
        vm_start();
    }
}