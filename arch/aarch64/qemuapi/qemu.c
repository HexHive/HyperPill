#include "qemu_c.h"
#include "qemuapi.h"

static void dump_registers(CPUARMState *env) {
    FILE *regs_file = fopen("regs.bin", "wb");
    if(!regs_file) {
        perror("Opening regs.bin");
        exit(1);
    }

    //CPUState *cpu;
    //CPU_FOREACH(cpu) {
        //struct ArchCPU *acpu = ARM_CPU(cpu);
        //CPUARMState *env = &(acpu->env);

        fwrite(env, 1, sizeof(CPUARMState), regs_file);
    //}

    fclose(regs_file);
}

static void dump_memory() {
    // TODO
}

static void restore_vm_state() {
    // TODO
}

static void dump_vm_state(CPUARMState *env) {
    //qemu_mutex_lock_iothread();
    printf("PAUSING\n");
    //pause_all_vcpus();
    vm_stop(RUN_STATE_PAUSED);
    //qemu_mutex_unlock_iothread();

    printf("DUMPING VM STATE\n");
    //dump_memory();
    //dump_registers(env);
    //qemu_mutex_unlock_iothread();
    /*Error *err = NULL;
    bool success = save_snapshot("hyperpill",
                  true, NULL, false, NULL, &err);
    //qemu_mutex_lock_iothread();
    if(!success) {
        printf("Error saving snapshot\n");
        error_report_err(err);
    } else {
        printf("Successful snapshot\n");
    }*/

    //qemu_mutex_lock_iothread();
    //printf("RESUMING...\n");

    /*if(vm_prepare_start(false)) {
        printf("COULDNT PREPARE START\n");
    }*/
    //vm_start();
    //resume_all_vcpus();
    printf("RESUMING DONE.\n");
    //qemu_mutex_unlock_iothread();

    if (runstate_is_running()) {
        printf("VM is running !\n");
    } else {
        printf("VM is stopped !\n");
    }

    if (qemu_mutex_iothread_locked()) {
        printf("iothread mutex locked\n");
    } else {
        printf("iothread mutex NOT locked\n");
    }
}

static void el_change_fn(ARMCPU *cpu, void *opaque) {
	CPUARMState *env = &cpu->env;
    CPUState *cs = env_cpu(env);

	//unsigned int new_el = env->exception.target_el;
	unsigned int cur_el = arm_current_el(env);

    if (cur_el == 2 && cs->exception_index == EXCP_HVC) {
        //printf("Call to Hypervisor!\n");
        if (env->xregs[0] == 0xdeadbeef) {
            printf("======== Hyperpill ! ========\n");
            //dump_vm_state(env);
            vm_stop(RUN_STATE_PAUSED);
            printf("VM stopped. You can now take a snapshot \
                    in QEMU monitor: savevm <snapshot_tag>\n");
        }
    }
}

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
    
    CPUState *cpu;
    CPU_FOREACH(cpu) {
        arm_register_el_change_hook(ARM_CPU(cpu), el_change_fn, NULL);
    }

    char *snapshot_tag = getenv("SNAPSHOT_TAG");
    if (snapshot_tag != NULL) {
        qemu_reload_vm(snapshot_tag);
        vm_start();
    }

    qemu_main_loop();
    qemu_cleanup(0);
}

//void cpu_physical_memory_rw(hwaddr addr, void *buf,
//                            hwaddr len, bool is_write); 