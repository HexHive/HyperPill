#ifndef HP_TESTS
#include "fuzz.h"

static void test_mem_write(uint64_t addr, size_t size, void *data) {
	BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, size, data);
}

static void test_mem_write_up_to_8(uint64_t addr, size_t size, uint64_t value) {
	BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, size, &value);
}

// addr: guest physical address
static void test_mmio_write(uint64_t addr, size_t size, uint64_t value) {
	printf("[INJECT MMIO WRITE] addr: 0x%lx value: 0x%lx \n", addr, value);
	if (!inject_write(addr, size, value))
		printf("inject write error/n");
	start_cpu();
}

static void test_out(uint16_t addr, uint16_t size, uint32_t value) {
	printf("[INJECT OUT] addr: 0x%x value: 0x%x \n", addr, size);
	if (!inject_out(addr, size, value))
		printf("inject out error/n");
	start_cpu();
}

static void test_clock_step() {
	printf("[INJECT CLOCK STEP]\n");
	if (!op_clock_step()) {
		printf("inject clock step error/n");
	}
}

#define HP_TESTS
#endif /* HP_TESTS */