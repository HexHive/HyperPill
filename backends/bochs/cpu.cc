#include "bochs.h"
#include "cpu/cpu.h"

extern BOCHSAPI BX_CPU_C bx_cpu;

void init_cpu() {
	BX_CPU(id)->initialize();
	BX_CPU(id)->reset(BX_RESET_HARDWARE);
	BX_CPU(id)->sanity_checks();
}