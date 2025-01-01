#include "fuzz.h"
#include "qemuapi.h"

bool cpu0_get_fuzztrace(void) {
    return __cpu0_get_fuzztrace();
}

void cpu0_set_fuzztrace(bool fuzztrace) {
    __cpu0_set_fuzztrace(fuzztrace);
}

extern "C" void cpu0_set_fuzz_executing_input(bool fuzzing) {
    if (!fuzzing) {
        qemu_signal_stop();
    } else {
        qemu_set_running();
    }
}

extern "C" bool cpu0_get_fuzz_executing_input(void) {
    return qemu_is_running();
}