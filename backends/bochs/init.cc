#include "bochs.h"
#include "cpu/cpu.h"
#include <stdio.h>
#include <stdlib.h>

extern void icp_init_params();
extern void init_cpu();
extern void bx_init_pc_system();

void icp_init_backend() {
	icp_init_params();
	init_cpu();
	bx_init_pc_system();
}