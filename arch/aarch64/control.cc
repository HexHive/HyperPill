#include "fuzz.h"
#include "qemuapi.h"

static bool aarch64_fuzztrace = false;

bool cpu0_get_fuzztrace(void) {
    return aarch64_fuzztrace;
}

void cpu0_set_fuzztrace(bool fuzztrace) {
    aarch64_fuzztrace = fuzztrace;
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