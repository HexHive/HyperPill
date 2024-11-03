#include "fuzz.h"

bool cpu0_get_fuzztrace(void) {
  return BX_CPU(id)->fuzztrace;
}

void cpu0_set_fuzztrace(bool fuzztrace) {
  BX_CPU(id)->fuzztrace = fuzztrace;
}

void cpu0_set_fuzz_executing_input(bool fuzzing) {
  BX_CPU(id)->fuzz_executing_input = fuzzing;
}

bool cpu0_get_fuzz_executing_input(void) {
  return BX_CPU(id)->fuzz_executing_input;
}