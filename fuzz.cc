#include "fuzz.h"
#include <tsl/robin_map.h>

#include <ctime>

enum cmds {
	OP_READ,
	OP_WRITE,
	OP_IN,
	OP_OUT,
	OP_PCI_WRITE,
	OP_MSR_WRITE,
	OP_VMCALL,
};

static bool log_ops = false;

std::map<bx_address, uint32_t> mmio_regions;
std::map<uint16_t, uint16_t> pio_regions;

static tsl::robin_map<bx_address, size_t> seen_dma;
uint16_t dma_start = 0;
uint16_t dma_len = 0;

/*
 * A pattern used to populate a DMA region or perform a memwrite. This is
 * useful for e.g. populating tables of unique addresses.
 * Example {.index = 1; .stride = 2; .len = 3; .data = "\x00\x01\x02"}
 * Renders as: 00 01 02   00 03 02   00 05 02   00 07 02 ...
 */
typedef struct {
	uint8_t index; /* Index of a byte to increment by stride */
	uint8_t stride; /* Increment each index'th byte by this amount */
	size_t len;
	const uint8_t *data;
} pattern;

/*
 * Allocate a block of memory and populate it with a pattern.
 */
static void *pattern_alloc(pattern p, size_t len) {
	int i;
	uint8_t *buf = (uint8_t *)malloc(len);
	uint8_t sum = 0;

	for (i = 0; i < len; ++i) {
		buf[i] = p.data[i % p.len];
		if ((i % p.len) == p.index) {
			buf[i] += sum;
			sum += p.stride;
		}
	}
	return buf;
}

void clear_seen_dma() {
	seen_dma.clear();
}

void fuzz_dma_read_cb(bx_phy_address addr, unsigned len, void *data) {
	uint8_t *buf;

	if (!fuzzing)
		return;

	if (seen_dma[addr + len - 1] == len)
		return;

	if (seen_dma.find(addr - 1) != seen_dma.end()) {
		seen_dma[addr + len - 1] = seen_dma[addr - 1] + len;
		seen_dma.erase(addr - 1);
	} else {
		seen_dma[addr + len - 1] = len;
	}
	size_t sectionlen = seen_dma[addr + len - 1];
	// might have multiple dma reads per op
	dma_len += len;

	if (sectionlen < 0x100) {
		// if DMA read is a reasonable size, obtain fuzz input for the
		// entire DMA read
		size_t l = len;
		buf = ic_ingest_buf(&l, SEPARATOR, SEPARATOR_LEN, -1, 0);
		if (buf == NULL) {
	        fuzz_emu_stop_unhealthy();
			return;
		}
		if (cpu0_get_fuzztrace() || log_ops) {
			printf("!dma inject: [HPA: %lx, GPA: %lx] len: %lx data: ",
			       addr, lookup_gpa_by_hpa(addr), len);
		}
		cpu0_mem_write_physical_page(addr, l, (void *)buf);
		memcpy(data, buf, l);
	} else if (sectionlen > 0x1000) {
	} else {
		uint8_t buf[100];
		size_t source = addr + len + 1 - sectionlen;
		if ((source + len) >> 12 != (source >> 12))
			source -= len;
		cpu0_mem_read_physical_page(source, len, buf);

		if (cpu0_get_fuzztrace() || log_ops) {
			printf("!dma inject: [HPA: %lx, GPA: %lx] len: %lx data: ",
			       addr, lookup_gpa_by_hpa(addr), len);
		}
		cpu0_mem_write_physical_page(addr, len, buf);
	}
}

unsigned int num_mmio_regions() {
	return mmio_regions.size();
}

static bx_address mmio_region(int idx) {
	for (auto &it : mmio_regions) {
		if (idx == 0) {
			return it.first;
		}
		idx -= 1;
	}
	return 0;
}

static bx_address mmio_region_size(bx_address addr) {
	return mmio_regions[addr];
}

static unsigned int num_pio_regions() {
	return pio_regions.size();
}

static uint16_t pio_region(int idx) {
	for (auto &it : pio_regions) {
		if (idx == 0)
			return it.first;
		idx -= 1;
	}
	return 0;
}

static uint16_t pio_region_size(uint16_t addr) {
	return pio_regions[addr];
}

bool inject_halt() {
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_HLT);
	BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 0);
	return true;
}

// INJECTORS
bool inject_write(bx_address addr, int size, uint64_t val) {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };
	BX_CPU(id)->VMwrite64(VMCS_64BIT_GUEST_PHYSICAL_ADDR, addr);

	uint32_t exit_reason =
		gpa2hpa(addr, NULL, NULL);
	/* printf("Exit reason: %lx\n", exit_reason); */
	if (!exit_reason)
		return false;
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, exit_reason);

	if (exit_reason == VMX_VMEXIT_EPT_VIOLATION)
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 2);
	else
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 0);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, addr);
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RAX, val);

	if (cpu0_get_fuzztrace() || log_ops) {
		printf("!write%d %lx %lx (reason: %lx)\n", size, addr, val,
		       exit_reason);
	}
	bx_address phy;
	int res = gva2hpa(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		cpu_physical_memory_write(phy, "\x88\x02", 2);
		break;
	case Word:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		cpu_physical_memory_write(phy, "\x66\x89\x02", 3);
		break;
	case Long:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		cpu_physical_memory_write(phy, "\x89\x02", 2);
		break;
	case Quad:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		cpu_physical_memory_write(phy, "\x48\x89\x02", 3);
		break;
	}
	return true;
}

bool inject_read(bx_address addr, int size) {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };

	uint32_t exit_reason =
		gpa2hpa(addr, NULL, NULL);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, exit_reason);

	BX_CPU(id)->VMwrite32(VMCS_64BIT_GUEST_PHYSICAL_ADDR, addr);

	if (exit_reason == VMX_VMEXIT_EPT_VIOLATION)
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 1);
	else
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 0);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RCX, addr);

	if (cpu0_get_fuzztrace() || log_ops) {
		printf("!read%d %lx\n", size, addr);
	}
	bx_address phy;
	int res = gva2hpa(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		cpu_physical_memory_write(phy,
					  "\x67\x8a\x01", // mov al,BYTE PTR
							  // [ecx]
					  3);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		break;
	case Word:
		cpu_physical_memory_write(phy,
					  "\x67\x66\x8b\x01", // mov ax,WORD PTR
							      // [ecx]
					  4);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 4);
		break;
	case Long:
		cpu_physical_memory_write(phy,
					  "\x67\x8b\x01", // mov eax,DWORD PTR
							  // [ecx]
					  3);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		break;
	case Quad:
		cpu_physical_memory_write(phy,
					  "\x48\x8b\x01", // mov rax,QWORD PTR
							  // [rcx]
					  3);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		break;
	}
	return true;
}

bool inject_in(uint16_t addr, uint16_t size) {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint64_t field_64 = 0;
	if (cpu0_get_fuzztrace() || log_ops) {
		printf("!in%d %x\n", size, addr);
	}
	bx_address phy;
	int res = gva2hpa(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		// writes the 'in' instruction with the appropriate size into
		// code
		cpu_physical_memory_write(phy, // L0 physical addr of $rip in
					       // L2, inside the saved VMCS
					  // uses VMREAD to read the VMCS's
					  // $rip, which is a GVA look for
					  // existing code somewhere that
					  // alreaedy does the conversion
					  "\xec", 1);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		break;
	case Word:
		cpu_physical_memory_write(phy, "\x66\xed", 2);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		field_64 |= 1; // access size
		break;
	case Long:
		cpu_physical_memory_write(phy, "\xed", 1);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		field_64 |= 3; // access size
		break;
	}
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON,
			      VMX_VMEXIT_IO_INSTRUCTION);

	field_64 |= (addr << 16); // port number
	field_64 |= (1 << 3); // //IN
	BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, field_64);
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, addr);
	return true;
}

bool inject_out(uint16_t addr, uint16_t size, uint32_t value) {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint64_t field_64 = 0;
	if (cpu0_get_fuzztrace() || log_ops) {
		printf("!out%d %x %x\n", size, addr, value);
	}
	bx_address phy;
	int res = gva2hpa(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		cpu_physical_memory_write(phy, "\xee", 1);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		break;
	case Word:
		cpu_physical_memory_write(phy, "\x66\xef", 2);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		field_64 |= 1; // access size
		break;
	case Long:
		cpu_physical_memory_write(phy, "\xef", 1);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		field_64 |= 3; // access size
		break;
	}

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, addr);

	// write value for out
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RAX, value);

	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON,
			      VMX_VMEXIT_IO_INSTRUCTION);

	field_64 |= (addr << 16);
	BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, field_64);
	return true;
}

uint32_t inject_pci_read(uint8_t device, uint8_t function, uint8_t offset) {
	uint32_t value;
	inject_out(0xcf8, 2,
		   (1U << 31) | (device << 11) | (function << 8) | offset);
	start_cpu();
	inject_in(0xcfc, 2);
	start_cpu();
	uint32_t val = BX_CPU(id)->gen_reg[BX_64BIT_REG_RAX].rrx;
	return val;
}

bool inject_pci_write(uint8_t device, uint8_t function, uint8_t offset,
		      uint32_t value) {
	inject_out(0xcf8, 2,
		   (1U << 31) | (device << 11) | (function << 8) | offset);
	start_cpu();
	inject_out(0xcfc, 2, value);
	start_cpu();
	return true;
}

bool inject_wrmsr(bx_address msr, uint64_t value) {
	bx_address phy;
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RAX, value & 0xFFFFFFFF);
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, value >> 32);

	int res = gva2hpa(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x30", 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_WRMSR);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RCX, msr);
	start_cpu();
	return true;
}

uint64_t inject_rdmsr(bx_address msr) {
	bx_address phy;
	int res = gva2hpa(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x32", 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_RDMSR);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RCX, msr);
	start_cpu();
	return (BX_CPU(id)->get_reg64(BX_64BIT_REG_RDX) << 32) |
	       (BX_CPU(id)->get_reg64(BX_64BIT_REG_RAX) & 0xFFFFFFFF);
}

/* OPERATIONS */

bool op_write() {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };
	uint8_t size;
	uint8_t base;
	uint32_t offset;
	uint64_t value;

	if (ic_ingest8(&size, 0, Quad))
		return false;
	if (!num_mmio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_mmio_regions() - 1))
		return false;
	bx_address addr = mmio_region(base);

	if (ic_ingest32(&offset, 0, mmio_region_size(addr) - 1))
		return false;
	addr += offset;
	switch (size) {
	case Byte:
		uint8_t val8;
		if (ic_ingest8(&val8, 0, -1))
			return false;
		value = val8;
		break;
	case Word:
		uint16_t val16;
		if (ic_ingest16(&val16, 0, -1))
			return false;
		value = val16;
		break;
	case Long:
		uint32_t val32;
		if (ic_ingest32(&val32, 0, -1))
			return false;
		value = val32;
		break;
	case Quad:
		if (ic_ingest64(&value, 0, -1))
			return false;
		break;
	}

	if (!inject_write(addr, size, value))
		return false;

	start_cpu();

	return true;
}

bool op_read() {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };
	uint8_t size;
	uint8_t base;
	// uint16_t offset;
	uint32_t offset;

	if (ic_ingest8(&size, 0, Quad))
		return false;
	if (!num_mmio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_mmio_regions() - 1))
		return false;
	bx_address addr = mmio_region(base);
	if (ic_ingest32(&offset, 0, mmio_region_size(addr) - 1))
		return false;
	addr += offset;

	if (!inject_read(addr, size))
		return false;

	start_cpu();
	return true;
}

bool op_out() {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint8_t size;
	uint8_t base;
	uint16_t offset;
	uint32_t value;

	if (ic_ingest8(&size, 0, Long))
		return false;
	if (!num_pio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_pio_regions() - 1))
		return false;

	bx_address addr = pio_region(base);
	if (ic_ingest16(&offset, 0, pio_region_size(addr) - 1))
		return false;

	bx_address phy;
	addr += offset;
	uint64_t field_64 = 0;
	if (addr == 0x160)
		return false;
	switch (size) {
	case Byte:
		uint8_t val8;
		if (ic_ingest8(&val8, 0, -1))
			return false;
		value = val8;
		break;
	case Word:
		uint16_t val16;
		if (ic_ingest16(&val16, 0, -1))
			return false;
		value = val16;
		break;
	case Long:
		uint32_t val32;
		if (ic_ingest32(&val32, 0, -1))
			return false;
		value = val32;
		break;
	}

	if (!inject_out(addr, size, value))
		return false;
	start_cpu();
	return true;
}

bool op_in() {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint8_t size;
	uint8_t base;
	uint16_t offset;

	if (ic_ingest8(&size, 0, Long))
		return false;
	if (!num_pio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_pio_regions() - 1))
		return false;

	bx_address addr = pio_region(base);
	if (ic_ingest16(&offset, 0, pio_region_size(addr) - 1))
		return false;
	addr += offset;

	if (!inject_in(addr, size))
		return false;
	start_cpu();
	return true;
}

static uint8_t pci_dev;
static uint8_t pci_fn;
void set_pci_device(uint8_t dev, uint8_t function) {
	pci_dev = dev;
	pci_fn = function;
	uint32_t original = inject_pci_read(pci_dev, pci_fn, 4);
	inject_pci_write(pci_dev, pci_fn, 4, original |= 0b111);
}

bool op_pci_write() {
	uint8_t device = pci_dev;
	uint8_t function = pci_fn;
	uint8_t offset;
	uint32_t value;
	if (!pci_dev)
		return false;

	if (ic_ingest8(&offset, 0, 64))
		return false;
	offset *= 4;
	if (offset == 4)
		return false;
	if (offset <= 0x10 + 24 && offset + 4 >= 0x10) // dont let us shift
						       // around BARS
		return false;
	if (offset <= 0x30 + 0x4 && offset + 4 >= 0x30) // dont let us shift
							// around BARS
		return false;
	if (offset <= 0x34 + 0x4 && offset + 4 >= 0x34) // dont let us shift
							// around BARS
		return false;
	if (offset <= 0x38 + 4 && offset + 4 >= 0x38) // dont let us shift
						      // around BARS
		return false;

	bx_address phy;
	int res = gva2hpa(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	uint32_t val32;
	if (ic_ingest32(&val32, 0, -1))
		return false;
	value = val32;
	if (offset == 4) // dont let us shift around ROM
		value = (value & ~(0b11)) | 0b10;
	inject_pci_write(device, function, offset, value);
	return true;
}

bool op_msr_write() {
	uint32_t msr;
	uint64_t value;
	if (ic_ingest32(&msr, 0, -1))
		return false;
	if (ic_ingest64(&value, 0, -1))
		return false;

	if (cpu0_get_fuzztrace() || log_ops) {
		printf("!wrmsr %lx = %lx\n", msr, value);
	}
	return inject_wrmsr(msr, value);
}

static bx_gen_reg_t vmcall_gpregs[16 + 4];
static __typeof__(BX_CPU(id)->vmm) vmcall_xmmregs BX_CPP_AlignN(64);
static uint32_t vmcall_enabled_regs;

void insert_register_value_into_fuzz_input(int idx) {
	vmcall_enabled_regs |= (1 << idx);
}

/* Strategy:
 * vmcalls don't have a set ABI. Here are the examples of how they work for
 * various hypervisors:
 *
 * XEN:     RAX (call code), RDI, RSI, RDX, R10 R8
 * Hyper-V: RCX (rich call code), RDX, R8, XMM0-XMM5
 * KVM:     RAX (call code), RBX, RCX, RDX
 *
 * Setting all of that from the fuzzer input would waste a ton of fuzzer input.
 * Idea: Fill all guest registers with a random pattern. If this pattern pops up
 * later down the line, we know that for some reason the hypervisor cares about
 * it. With that information, we can modify the input to specify that the
 * corresponding register should be fuzzer provided.
 *
 * So a VMCALL looks like:
 * [opcode]
 * [bitfield to select which registers are fuzzer provided]
 * [the corresponding registers in natural order]
 */
bool op_vmcall() {
	static uint8_t local_dma[4096]; // Used to make a copy of dma data
					// before rewriting regs
	size_t local_dma_len; // Used to make a copy of dma data before
			      // rewriting regs
	const uint64_t fuzzable_regs_bitmap = (0b11111111111111001110);
	if (ic_ingest32(&vmcall_enabled_regs, 0, -1, true))
		return false;

	static bx_gen_reg_t gen_reg_snap[BX_GENERAL_REGISTERS + 4];

	static uint8_t xmm_reg_snap[sizeof(BX_CPU(id)->vmm)];

	// If the op was skipped, we need to reset the register state
	memcpy(vmcall_gpregs, BX_CPU(id)->gen_reg, sizeof(BX_CPU(id)->gen_reg));
	memcpy(vmcall_xmmregs, BX_CPU(id)->vmm, sizeof(BX_CPU(id)->vmm));
	vmcall_enabled_regs &= fuzzable_regs_bitmap;
	for (int i = 0; i < 16; i++) {
		if ((vmcall_enabled_regs >> i) & 1) {
			if (i == BX_64BIT_REG_RSP)
				continue;
			uint64_t val;
			if (ic_ingest64(&val, 0, -1)) {
				return false;
			}
			vmcall_gpregs[i].rrx = val;
		}
	}
	for (int i = 0; i < BX_XMM_REGISTERS; i++) {
		if ((vmcall_enabled_regs >> (16 + i)) & 1) {
			uint8_t *value =
				ic_ingest_len(sizeof(BX_CPU(id)->vmm[i]));
			if (!value) {
				return false;
			}
			memcpy(&vmcall_xmmregs[i], value,
			       sizeof(BX_CPU(id)->vmm[i]));
		}
	}

	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_VMCALL);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);

	bx_address phy;
	int res = gva2hpa(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x01\xc1", 3);

	memcpy(BX_CPU(id)->gen_reg, vmcall_gpregs, sizeof(BX_CPU(id)->gen_reg));
	memcpy(BX_CPU(id)->vmm, vmcall_xmmregs, sizeof(BX_CPU(id)->vmm));

	uint8_t *dma_start = ic_get_cursor();

	if (cpu0_get_fuzztrace() || log_ops) {
		printf("!hypercall %lx\n", vmcall_gpregs[BX_64BIT_REG_RCX]);
	}
	start_cpu();
	/* printf("Hypercall %lx Result: %lx\n",vmcall_gpregs[BX_64BIT_REG_RCX],
	 * BX_CPU(id)->get_reg64(BX_64BIT_REG_RAX)); */

	uint8_t *dma_end = ic_get_cursor();

	local_dma_len = dma_end - dma_start;
	if (local_dma_len > sizeof(local_dma)) {
	    fuzz_emu_stop_unhealthy();
		return false;
	}
	memcpy(local_dma, dma_start, local_dma_len);

	ic_erase_backwards_until_token();
	vmcall_enabled_regs &= fuzzable_regs_bitmap;
	uint8_t opcode = OP_VMCALL;
	if (!ic_append(&opcode, sizeof(opcode)))
	    fuzz_emu_stop_unhealthy();
	if (!ic_append(&vmcall_enabled_regs, sizeof(vmcall_enabled_regs)))
	    fuzz_emu_stop_unhealthy();
	for (int i = 0; i < 16; i++) {
		if ((vmcall_enabled_regs >> i) & 1) {
			if (!ic_append(&vmcall_gpregs[i],
				       sizeof(vmcall_gpregs[i])))
	            fuzz_emu_stop_unhealthy();
		}
	}
	for (int i = 0; i < BX_XMM_REGISTERS; i++) {
		if ((vmcall_enabled_regs >> (16 + i)) & 1) {
			if (!ic_append(&vmcall_xmmregs[i],
				       sizeof(BX_CPU(id)->vmm[i])))
                fuzz_emu_stop_unhealthy();
		}
	}

	if (!ic_append(local_dma, local_dma_len))
        fuzz_emu_stop_unhealthy();
	return true;
}

extern bool fuzz_unhealthy_input, fuzz_do_not_continue, fuzz_should_abort;
void fuzz_run_input(const uint8_t *Data, size_t Size) {
	bool (*ops[])() = {
		[OP_READ] = op_read,
		[OP_WRITE] = op_write,
		[OP_IN] = op_in,
		[OP_OUT] = op_out,
		[OP_PCI_WRITE] = op_pci_write,
		[OP_MSR_WRITE] = op_msr_write,
		[OP_VMCALL] = op_vmcall,
	};
	static const int nr_ops = sizeof(ops) / sizeof((ops)[0]);
	uint8_t op;

	static void *fuzz_legacy, *fuzz_hypercalls;
	static int inited;
	if (!inited) {
		inited = 1;
		fuzz_legacy = getenv("FUZZ_LEGACY");
		fuzz_hypercalls = getenv("FUZZ_HYPERCALLS");
		log_ops = getenv("LOG_OPS") || cpu0_get_fuzztrace();
	}

	//if (log_ops)
		//printf("!new input (length %d)\n", Size);
	ic_new_input(Data, Size);
	uint16_t start = 0;
	int nops = 0;
	uint8_t *input_start = ic_get_cursor();
	do {
		dma_start = ic_get_cursor() - input_start;
		dma_len = 0;
		if (fuzz_legacy) {
			if (ic_ingest8(&op, OP_READ, OP_OUT, true)) {
				ic_erase_backwards_until_token();
				ic_subtract(4);
				continue;
			}
		} else if (fuzz_hypercalls) {
			if (ic_ingest8(&op, OP_MSR_WRITE, OP_VMCALL, true)) {
				ic_erase_backwards_until_token();
				ic_subtract(4);
				continue;
			}
		} else { /* Fuzz Everything */
			if (ic_ingest8(&op, 0, OP_VMCALL, true)) {
				ic_erase_backwards_until_token();
				ic_subtract(4);
				continue;
			}
		}
		if (!ops[op]()) {
			ic_erase_backwards_until_token();
			ic_subtract(4);
			continue;
		}
		if (fuzz_unhealthy_input || fuzz_do_not_continue)
			break;
		if (new_op(op, start, ic_get_cursor() - input_start, dma_start,
			   dma_len) >= 8)
			break;
	} while (ic_advance_until_token(SEPARATOR, 4));

	size_t dummy;
	uint8_t *output = ic_get_output(&dummy); // Set the output and op log
}

void add_pio_region(uint16_t addr, uint16_t size) {
	pio_regions[addr] = size;
	printf("pio_regions %d = %lx + %lx\n", pio_regions.size(), addr, size);
}
void add_mmio_region(uint64_t addr, uint64_t size) {
	mmio_regions[addr] = size;
	printf("mmio_regions %d = %lx + %lx\n", mmio_regions.size(), addr,
	       size);
}
void add_mmio_range_alt(uint64_t addr, uint64_t end) {
	add_mmio_region(addr, end - addr);
}
void init_regions(const char *path) {
	open_db(path);
	if (getenv("FUZZ_ENUM")) {
		enum_pio_regions();
		enum_mmio_regions();
        exit(0);
	}
	if (getenv("MANUAL_RANGES")) {
		load_manual_ranges(getenv("MANUAL_RANGES"),
				   getenv("RANGE_REGEX"), pio_regions,
				   mmio_regions);
	} else {
		load_regions(pio_regions, mmio_regions);
	}
}
