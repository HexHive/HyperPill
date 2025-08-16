#include "qemu.h"

bool cpu0_get_fuzztrace(void) {
    return QEMU_CPU(0)->fuzztrace;
}

void cpu0_set_fuzztrace(bool fuzztrace) {
    QEMU_CPU(0)->fuzztrace = fuzztrace;
}

void cpu0_set_fuzz_executing_input(bool fuzzing) {
    QEMU_CPU(0)->fuzz_executing_input = fuzzing;
}

bool cpu0_get_fuzz_executing_input(void) {
    return QEMU_CPU(0)->fuzz_executing_input;
}

void cpu0_run_loop() {
    vm_start();
    if (is_gdbstub_enabled()) {
        runstate_set(RUN_STATE_PAUSED);
    }

    int status;

    while (cpu0_get_fuzz_executing_input()) {
        status = qemu_main_loop();
        if (status) {
            fuzz_emu_stop_normal();
        }
    }
}

void cpu0_run_loop_and_ret() {
    vm_start();

    main_loop_wait(false);
}
