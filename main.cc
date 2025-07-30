#include "fuzz.h"
#include <cstdint>

int in_timer_mode = 0;
uint64_t timer_mod[5] = {0};
bool hack_timer_mod = false;

bool master_fuzzer;
bool verbose = 1;

bool fuzz_unhealthy_input = false; /* We reached an execution timeout */
bool fuzz_do_not_continue = false; /* Don't inject new instructions. */
bool fuzz_should_abort = false;    /* We got a crash. */

bool fuzzing;
static bool executing_input;

BOCHSAPI BX_CPU_C bx_cpu = BX_CPU_C(0);
BOCHSAPI BX_CPU_C shadow_bx_cpu;

uint64_t vmcs_addr;
uint64_t guest_rip; /* Entrypoint. Reset after each op */

static void *log_writes;
static bool fuzzenum;

uint64_t icount_limit_floor = 200000;
uint64_t icount_limit = 50000000;

static unsigned long int icount, pio_icount;

static void dump_hex(const uint8_t *data, size_t len) {
	for (int i = 0; i < len; i++)
		printf("%02x ", data[i]);
	printf("\n");
}

void dump_regs() {
	static const char *general_64bit_regname[17] = {
		"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8",
		"r9",  "r10", "r11", "r12", "r13", "r14", "r15", "rip"
	};
	for (int i = 0; i <= BX_GENERAL_REGISTERS; i++) {
		printf("REG%d (%s) = %016lx\n", i, general_64bit_regname[i],
		       BX_CPU(id)->gen_reg[i].rrx);
	}
	printf("FLAGS: %x\n", BX_CPU(id)->eflags);
	fflush(stdout);
	fflush(stderr);
}

static void init_cpu(void) {
	BX_CPU(id)->initialize();
	BX_CPU(id)->reset(BX_RESET_HARDWARE);
	BX_CPU(id)->sanity_checks();
}

void start_cpu() {
	if (fuzzing && (fuzz_unhealthy_input || fuzz_do_not_continue))
		return;

	srand(1); /* rdrand */
	BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx = guest_rip;
	icount = 0;
	pio_icount = 0;
	clear_seen_dma();
	if (BX_CPU(id)->fuzztrace) {
		dump_regs();
	}
	reset_op_cov();

	BX_CPU(id)->fuzz_executing_input = true;
	if (bx_dbg.gdbstub_enabled)
		hp_gdbstub_debug_loop();
	while (BX_CPU(id)->fuzz_executing_input) {
		BX_CPU(id)->cpu_loop();
	}
	if (fuzz_unhealthy_input || fuzz_do_not_continue)
		return;
	BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx = guest_rip; // reset $RIP

	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	assert(res == 1); // Guest page table should be guarded
	if (phy > maxaddr || !res) {
		fuzz_do_not_continue = true;
	}
}

/*
 * There are multiple ways to break out of the emulator:
 * fuzz_emu_stop_normal :
 *      A healthy stop (after hypervisor re-enter into the VM).
 * fuzz_emu_stop_unhealthy :
 *      We reached some timeout or error condition. Do not attmept to inject
 *      more operations and do not save the input in our queue.
 * fuzz_emu_stop_crash :
 *      There was a crash. Potentially print some info. Do not attempt to inject
 *      more operations.
 */

static void fuzz_emu_stop() {
	BX_CPU(id)->fuzz_executing_input = false;
}

void fuzz_emu_stop_normal(){
    fuzz_emu_stop();
}

void fuzz_emu_stop_unhealthy(){
	fuzz_emu_stop();
    fuzz_do_not_continue = 1;
    fuzz_unhealthy_input = 1;
}

void fuzz_emu_stop_crash(const char *type){
	fuzz_emu_stop_unhealthy();
	fuzz_should_abort = 1;
	if (type) {
		printf(".crash %s\n", type);
	} else {
		printf(".crash\n");
	}
    if(master_fuzzer) {
        print_stacktrace();
        ic_dump();
    }
}

void fuzz_hook_exception(unsigned vector, unsigned error_code) {
	if (verbose)
		printf("Exception: 0x%x 0x%x\n", vector, error_code);
}

void fuzz_hook_hlt() {
	fuzz_emu_stop_crash("hlt\n");
	return;
}

unsigned long int get_icount() {
	return icount;
}

unsigned long int get_pio_icount() {
	return pio_icount;
}

void reset_bx_vm() {
	bx_cpu = shadow_bx_cpu;
	if (BX_CPU(id)->vmcs_map)
		BX_CPU(id)->vmcs_map->set_access_rights_format(VMCS_AR_OTHER);
	fuzz_reset_memory();
}

void fuzz_instr_interrupt(unsigned cpu, unsigned vector) {
	if (vector == 3) {
        fuzz_emu_stop_crash("debug interrupt");
	}
}

void fuzz_instr_after_execution(bxInstruction_c *i) {
	if (hack_timer_mod && i->getIaOpcode() == 0x4b8 /*CALL_Jq*/) {
		static uint64_t rdi, rsi; // context
		uint64_t rip = BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx;
		if (rip == timer_mod[0] || rip == timer_mod[1] || rip == timer_mod[2] || rip == timer_mod[3]) {
			if (in_timer_mode == 0) {
				uint64_t anchor = BX_CPU(id)->pop_64() - 5; // assume CALL_Ja
				rdi = BX_CPU(id)->gen_reg[BX_64BIT_REG_RDI].rrx;
				rsi = BX_CPU(id)->gen_reg[BX_64BIT_REG_RSI].rrx;
				// printf("call timer_mod(ts=0x%lx, expire_time=0x%lx), ", rdi, rsi);
				BX_CPU(id)->set_reg64(BX_64BIT_REG_RDI, 1 /*CLOCK_VIRTUAL*/);
				BX_CPU(id)->prev_rip = timer_mod[4];
				BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx = timer_mod[4];
				BX_CPU(id)->push_64(anchor);
				BX_CPU(id)->invalidate_prefetch_q();
				in_timer_mode++;
			} else if (in_timer_mode == 1) {
				uint64_t current = BX_CPU(id)->get_reg64(BX_64BIT_REG_RAX);
				// printf("while current=0x%lx\n", current);
				BX_CPU(id)->set_reg64(BX_64BIT_REG_RSI, current);
				BX_CPU(id)->set_reg64(BX_64BIT_REG_RDI, rdi);
				BX_CPU(id)->prev_rip = rip;
				BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx = rip;
				BX_CPU(id)->invalidate_prefetch_q();
				in_timer_mode = 2;
			}
		}
	}
}

void fuzz_instr_before_execution(bxInstruction_c *i) {
	handle_breakpoints(i);
	handle_syscall_hooks(i);
	if (!fuzzing && !fuzzenum)
		return;

	/* Check Icount limits */
	if (icount > icount_limit && fuzzing) {
		printf("icount abort %d\n", icount);
	    fuzz_emu_stop_unhealthy();
	}
    icount++;
    pio_icount++;
}

static void usage() {
	printf("The following environment variables must be set:\n");
	printf("ICP_MEM_PATH\n");
	printf("ICP_REGS_PATH\n");
	printf("ICP_VMCS_LAYOUT_PATH\n");
	printf("ICP_VMCS_ADDR\n");
	exit(-1);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	static void *ic_test = getenv("FUZZ_IC_TEST");
	static int done;
	if (BX_CPU(id)->fuzztrace)
		printf("NEW INPUT\n");
	if (!done) {
		if (!log_writes)
			log_writes = getenv("LOG_WRITES");
		if (!getenv("NOCOV")) {
			init_sourcecov(
				strtoll(getenv("LINK_OBJ_BASE"), NULL, 16));
		}
		setup_periodic_coverage();
	}

	check_write_coverage();

	/* Reset vars used to early abort input */
	fuzz_do_not_continue = false;
	fuzz_unhealthy_input = false;
	fuzz_should_abort = false;
	reset_cur_cov();

	fuzzing = true;
	fuzz_run_input(Data, Size);
	fuzzing = false;

	if (fuzz_should_abort) abort();

	size_t len;
	uint8_t *output = ic_get_output(&len);
	if (len == 0 || fuzz_unhealthy_input || !done) {
		uint8_t *dummy = (uint8_t *)"AAA";
		__fuzzer_set_output(dummy, 1);
		reset_bx_vm();
		done = 1;
		return 0;
	}
	done = 1;

	reset_bx_vm();

	/*
	 * The IC_TEST mode
	 */
	if (ic_test && !fuzz_unhealthy_input) {
		tsl::robin_set<bx_address> original_coverage = cur_input;
		size_t len, len2;
		uint8_t *output = ic_get_output(&len);
		uint8_t *newdata = (uint8_t *)malloc(len);
		memcpy(newdata, output, len);
		fuzz_unhealthy_input = false;
		reset_cur_cov();
		fuzzing = true;
		printf("Rerun:\n");
		fuzz_run_input(newdata, len);
		fuzzing = false;

		output = ic_get_output(&len2);
		if (len != len2 || memcmp(output, newdata, len)) {
			printf("Detected mismatch. Original Input %ld. IC Output1: %ld IC "
			       "Output2: %ld\n",
			       Size, len, len2);
			printf("Original Input: ");
			dump_hex(Data, Size);
			printf("IC Output 1     : ");
			dump_hex(newdata, len);
			printf("IC Output 2     : ");
			dump_hex(output, len2);
			fflush(stdout);
			fflush(stdout);
			exit(1);
		}
		if (original_coverage != cur_input) {
			printf("Detected Coverage mismatch\n");
			printf("Original Input: ");
			dump_hex(Data, Size);
			printf("IC Output     : ");
			dump_hex(newdata, len);
			fflush(stdout);
			exit(1);
		}
		free(newdata);
		reset_bx_vm();
	}
	return fuzz_unhealthy_input != 0;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
	/* Path to VM Snapshot */
	char *mem_path = getenv("ICP_MEM_PATH");
	char *regs_path = getenv("ICP_REGS_PATH");
	char *icp_db_path = getenv("ICP_DB_PATH");
	verbose = getenv("VERBOSE");

	/* The Layout of the VMCS is specific to the CPU where the snapshot was
	 * collected, so we also need to load a mapping of VMCS encodings to
	 * offsets
	 */
	char *vmcs_shadow_layout_path = getenv("ICP_VMCS_LAYOUT_PATH");

	/*
	 * Location of VMCS is not contained in either the mem or regs, so
	 * speicify it manually. It can be obtained from the KVM state dump into
	 * syslog.
	 */
	char *vmcs_addr_str = getenv("ICP_VMCS_ADDR");

	if (!(mem_path && regs_path && vmcs_shadow_layout_path &&
	      vmcs_addr_str))
		usage();

	vmcs_addr = strtoll(vmcs_addr_str, NULL, 16);

	/* Bochs-specific initialization. (e.g. CPU version/features). */
	if (getenv("GDB")) {
		bx_dbg.gdbstub_enabled = 1;
	}
	icp_init_params();
	init_cpu();
	bx_init_pc_system();

	BX_CPU(id)->fuzzdebug_gdb = getenv("GDB");
	BX_CPU(id)->fuzztrace = (getenv("FUZZ_DEBUG_DISASM") != 0);

	/* Load the snapshot */
	printf(".loading memory snapshot from %s\n", mem_path);
	icp_init_mem(mem_path);
	fuzz_watch_memory_inc();

	icp_init_shadow_vmcs_layout(vmcs_shadow_layout_path);
	printf(".loading register snapshot from %s\n", regs_path);
	icp_init_regs(regs_path);

	/* The current VMCS address is part of the CPU-state, but it is not part
	 * of the memory or register snapshot. As such, we load it (and adjacent
	 * internal Bochs pointers) separately.
	 */
	printf(".vmcs addr set  to %lx\n", vmcs_addr);
	icp_set_vmcs(vmcs_addr);

	/* Dump disassembly and CMP hooks? */

	fuzz_walk_ept();

	/* WIP: Tweak the VMCS/L2 state. E.g. set up our own page-tables for L2
	 * and ensure that the hypervisor thinks L2 is running privileged
	 * code/ring0 code.
	 */
	vmcs_fixup();
	/* fuzz_walk_cr3(); */

	/*
	 * Previously, we identified all of L2's pages. However, we want to
	 * avoid overwriting the L2's page-tables, as this might cause us to end
	 * up with crashes that are impossible to achieve in practice. So let's
	 * identify L2's page-tables and remove them from the list of hooked L2
	 * pages.
	 *
	 * Example: We inject a MMIO read into HV
	 *
	 * HV needs to disassemble the current L2 instruction to figure out
	 * where to place the result of the MMIO read.
	 *
	 * To do that it needs to take L2's RIP and convert it from a virtual
	 * address to a physical address.
	 *
	 * To do that it needs to walk L2's page tables. If we let
	 * the fuzzer hook reads from the page-table it might cause HV to crash
	 * but it's not clear whether it would be possible to actually cause the
	 * crash in practice (if the page-table was corrupted by the fuzzer, the
	 * MMIO exit wouldn't have happened in the first place
	 */
	ept_mark_page_table();

	/* Translate the guest's RIP in the VMCS to a physical-address */
	ept_locate_pc();

	/* Save guest RIP so that we can restore it after each fuzzer input */
	guest_rip = BX_CPU(id)->get_rip();

	/* For addr -> symbol */
	if (getenv("SYMBOLS_DIR"))
		load_symbolization_files(getenv("SYMBOLS_DIR"));

	/* For symbol - > addr (for breakpoints)*/
	if (getenv("SYMBOL_MAPPING")) {
		load_symbol_map(getenv("SYMBOL_MAPPING"));
		if (getenv("HACK_TIMER_MOD")) {
			timer_mod[0] = sym_to_addr("qemu-system", "timer_mod");
			timer_mod[1] = sym_to_addr("qemu-system", "timer_mod_anticipate");
			timer_mod[2] = sym_to_addr("qemu-system", "timer_mod_ns");
			timer_mod[3] = sym_to_addr("qemu-system", "timer_mod_anticipate_ns");
			timer_mod[4] = sym_to_addr("qemu-system", "qemu_clock_get_ns");
			hack_timer_mod = true;
		}
	}

	BX_CPU(id)->TLB_flush();
	fuzz_walk_ept();
	vmcs_fixup();
	ept_mark_page_table();
	init_register_feedback();

	if (getenv("LINK_MAP") && getenv("LINK_OBJ_REGEX"))
		load_link_map(getenv("LINK_MAP"), getenv("LINK_OBJ_REGEX"),
			      strtoll(getenv("LINK_OBJ_BASE"), NULL, 16));

	uint32_t pciid = 0;
	if (getenv("PCI_ID")) {
		pciid = strtol(getenv("PCI_ID"), NULL, 16);
		for (int i = 0; i < 32; i++)
			for (int j = 0; j < 8; j++) {
				uint32_t id = inject_pci_read(i, j, 0x0);
				if ((((id & 0xFFFF) << 16) | (id >> 16)) ==
				    pciid) {
					printf("Identified DEVICE %x FUNCTION %x : %04x:%04x\n",
					       i, j, id & 0xFFFF, id >> 16);
					set_pci_device(i, j);
				}
			}
	}
	if (getenv("KVM")) {
		add_pc_range(0, 0x7fffffffffff);
		apply_breakpoints_linux();
    }
	/*
	 * make a copy of the bochs CPU state, which we use to reset the CPU
	 * state after each fuzzer input
	 */
	shadow_bx_cpu = bx_cpu;

	/* Start tracking accesses to the memory so we can roll-back changes
	 * after each fuzzer input */
	fuzz_watch_memory_inc();
	reset_bx_vm();

	/* Enumerate or Load the cached list of PIO and MMIO Regions */
	fuzzenum = true;
	init_regions(icp_db_path);
	fuzzenum = false;

	return 0;
}
