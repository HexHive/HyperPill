#ifndef HP_TESTS
#include "fuzz.h"

static void test_mem_write_up_to_8(uint64_t addr, size_t size, uint64_t data) {
	BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, size, &data);
}

// addr: guest physical address
static void test_mmio_write(uint64_t addr, size_t size, uint64_t data) {
	printf("[INJECT MMIO WRITE] addr: 0x%ld value: 0x%lx \n", addr, data);
	if (!inject_write(addr, size, data))
		printf("inject write error/n");
	start_cpu();
}

#define HP_TESTS
#endif /* HP_TESTS */