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
	// TODO
	CPUARMState *env = &cpu->env;
    CPUState *cs = env_cpu(env);

	//unsigned int new_el = env->exception.target_el;
	unsigned int cur_el = arm_current_el(env);

    if (cur_el == 2 && cs->exception_index == EXCP_HVC) {
        printf("Call to Hypervisor!\n");
        if (env->xregs[0] == 0xdeadbeef) {
            printf("======== Hyperpill ! ========\n");
            dump_vm_state(env);
            printf("FINISHED DUMPING\n");
        }
    }
}

void init_qemu(int argc, char **argv) {
    qemu_init(argc, argv);
    
    /*CPUState *cpu;
    CPU_FOREACH(cpu) {
        arm_register_el_change_hook(ARM_CPU(cpu), el_change_fn, NULL);
    }*/

    vm_stop(RUN_STATE_RESTORE_VM);

    Error *err;
    bool success = load_snapshot("hyperpill", NULL, false, NULL, &err);
    if(!success) {
        printf("Error loading snapshot\n");
        error_report_err(err);
    } else {
        printf("Successful snapshot load\n");
    }

    vm_start();

    qemu_main_loop();
    qemu_cleanup(0);
}

//void arm_register_el_change_hook(ARMCPU *cpu, ARMELChangeHookFn *hook, void
//        *opaque);

//void cpu_physical_memory_rw(hwaddr addr, void *buf,
//                            hwaddr len, bool is_write); 
//void qemu_init(int argc, char **argv);
//int qemu_main_loop(void);
//void qemu_cleanup(int);