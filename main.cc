#include "fuzz.h"
#include <cstdint>
#include <signal.h>

#if defined(HP_BACKEND_BOCHS)
int in_timer_mode = 0;
uint64_t timer_mod[5] = {0};
bool hack_timer_mod = false;
#endif

bool master_fuzzer;
bool verbose = 1;

bool fuzz_unhealthy_input = false; /* We reached an execution timeout */
bool fuzz_do_not_continue = false; /* Don't inject new instructions. */
bool fuzz_should_abort = false;    /* We got a crash. */

bool fuzzing;

#if defined(HP_X86_64)
uint64_t vmcs_addr;
#endif

uint64_t guest_rip; /* Entrypoint. Reset after each op */

static void *log_writes;
static bool fuzzenum;

uint64_t icount_limit_floor = 200000;
#if defined(HP_BACKEND_BOCHS)
uint64_t icount_limit = 50000000;
#elif defined(HP_BACKEND_QEMU)
uint64_t icount_limit = 5000000;
#endif

static unsigned long int icount;
#if defined(HP_X86_64)
static unsigned long int pio_icount;
#endif

static void dump_hex(const uint8_t *data, size_t len) {
	for (int i = 0; i < len; i++)
		printf("%02x ", data[i]);
	printf("\n");
}

void start_cpu() {
	if (fuzzing && (fuzz_unhealthy_input || fuzz_do_not_continue))
		return;

	srand(1); /* rdrand */
	cpu0_set_pc(guest_rip);
	icount = 0;
#if defined(HP_X86_64)
	pio_icount = 0;
#endif
	clear_seen_dma();
	if (cpu0_get_fuzztrace()) {
		dump_regs();
	}
	reset_op_cov();
	cpu0_set_fuzz_executing_input(true);
	if (is_gdbstub_enabled()) {
		hp_gdbstub_debug_loop();
	}
	cpu0_run_loop();
	if (fuzz_unhealthy_input || fuzz_do_not_continue)
		return;
	cpu0_set_pc(guest_rip); // reset $RIP

#if defined(HP_X86_64)
	bx_address phy;
	int res = gva2hpa(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	assert(res == 1); // Guest page table should be guarded
	if (phy > maxaddr || !res) {
		fuzz_do_not_continue = true;
	}
#endif
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
	cpu0_set_fuzz_executing_input(false);
}

void fuzz_emu_stop_normal(){
    fuzz_emu_stop();
    fuzz_do_not_continue = 1;
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
	verbose_printf("Exception: 0x%x 0x%x\n", vector, error_code);
}

void fuzz_hook_hlt() {
	fuzz_emu_stop_crash("hlt\n");
	return;
}

unsigned long int get_icount() {
	return icount;
}

#if defined(HP_X86_64)
unsigned long int get_pio_icount() {
	return pio_icount;
}
#endif

void reset_vm() {
	restore_cpu();
#if defined(HP_X86_64)
	icp_set_vmcs_map();
#endif
	fuzz_reset_memory();
}

void fuzz_interrupt(unsigned cpu, unsigned vector) {
	if (vector == 3) {
        fuzz_emu_stop_crash("debug interrupt");
	}
}

void fuzz_after_execution(hp_instruction *i) {
#if defined(HP_BACKEND_BOCHS)
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
#endif
}

void fuzz_before_execution(uint64_t ic) {
	if (!fuzzing && !fuzzenum)
		return;

	/* Check Icount limits */
	if (icount > icount_limit && fuzzing) {
		printf("icount abort %d\n", icount);
	    fuzz_emu_stop_unhealthy();
	}
    icount += ic;
#if defined(HP_X86_64)
    pio_icount += ic;
#endif
}

static void usage() {
	printf("The following environment variables must be set:\n");
	printf("ICP_MEM_PATH\n");
	printf("ICP_REGS_PATH\n");
#if defined(HP_X86_64)
	printf("ICP_VMCS_LAYOUT_PATH\n");
	printf("ICP_VMCS_ADDR\n");
#endif
	exit(-1);
}

static void cleanup() {
	pid_t pid = getpid();
	std::string filename = "seen_edges.drcov"; //  + std::to_string(pid) + ".log";
	save_seen_edges(filename);
}

static void handle_signal(int sig) {
	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGALRM:
		cleanup();
	default:
		break;
	}
	exit(1);
}

#if defined(HP_INPUT_GEN_TRUMAN)
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed) {
    return virtfuzzCustomMutator(Data, Size, MaxSize, Seed);
}

size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                 const uint8_t *data2, size_t size2,
                                 uint8_t *out, size_t max_out_size,
                                 unsigned int seed) {
    return virtfuzzCustomCrossOver(data1, size1, data2, size2, out, max_out_size, seed);
}
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	static void *ic_test = getenv("FUZZ_IC_TEST");
	static int done;
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

	if (fuzz_should_abort) {
		cleanup();
		abort();
	}

	size_t len;
	uint8_t *output = ic_get_output(&len);
	if (len == 0 || fuzz_unhealthy_input || !done) {
		uint8_t *dummy = (uint8_t *)"AAA";
		__fuzzer_set_output(dummy, 1);
		reset_vm();
		done = 1;
		return 0;
	}
	done = 1;

	reset_vm();

	/*
	 * The IC_TEST mode
	 */
	if (ic_test && !fuzz_unhealthy_input) {
		tsl::robin_set<hp_address> original_coverage = cur_input;
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
		reset_vm();
	}
	return fuzz_unhealthy_input != 0;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
	/* Path to VM Snapshot */
	char *mem_path = getenv("ICP_MEM_PATH");
	char *regs_path = getenv("ICP_REGS_PATH");
	char *icp_db_path = getenv("ICP_DB_PATH");
	verbose = getenv("VERBOSE");

#if defined(HP_X86_64)
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
#elif defined(HP_AARCH64)
	if (!(mem_path && regs_path))
		usage();
#endif

#ifdef HP_INPUT_GEN_TRUMAN
	const char *device_model_file = getenv("TRUMAN_DBM");
	if (!device_model_file) {
		printf("The TRUMAN_DBM must be set\n");
		exit(-1);
	}
	int result = init_device_model(device_model_file);
	if (result == -1) {
		printf("The initialization of TRUMAN_DBM fails\n");
		exit(-1);
	}
#endif

#if defined(HP_X86_64)
	vmcs_addr = strtoll(vmcs_addr_str, NULL, 16);
#endif

	icp_init_backend();
	icp_init_gdb();

	bool fuzztrace = (getenv("FUZZ_DEBUG_DISASM") != 0);
	cpu0_set_fuzztrace(fuzztrace);

	/* Load the snapshot */
	printf(".loading memory snapshot from %s\n", mem_path);
	icp_init_mem(mem_path);
	fuzz_watch_memory_inc();

#if defined(HP_X86_64)
	icp_init_shadow_vmcs_layout(vmcs_shadow_layout_path);
#endif
	printf(".loading register snapshot from %s\n", regs_path);
	icp_init_regs(regs_path);

#if defined(HP_X86_64)
	/* The current VMCS address is part of the CPU-state, but it is not part
	 * of the memory or register snapshot. As such, we load it (and adjacent
	 * internal Bochs pointers) separately.
	 */
	printf(".vmcs addr set  to %lx\n", vmcs_addr);
	icp_set_vmcs(vmcs_addr);
#endif

	/* Dump disassembly and CMP hooks? */

	// Second Level Address Translation (SLAT)
	// Intel's implementation of SLAT is Extended Page Table (EPT)
	// AARCH64's implementation of SLAT is Stage-2 Page Tabels (S2PT)
	fuzz_walk_slat();

	/* Tweak the L2 state. E.g. set up our own page-tables for L2
	 * and ensure that the hypervisor thinks L2 is running privileged
	 * code/ring0 code.
	 */
	l2_fixup();

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
	slat_mark_page_table();

	/* Translate the guest's RIP to a physical-address */
	slat_locate_pc();

	/* Save guest RIP so that we can restore it after each fuzzer input */
	guest_rip = cpu0_get_pc();

	/* For addr -> symbol */
	if (getenv("SYMBOLS_DIR"))
		load_symbolization_files(getenv("SYMBOLS_DIR"));

	/* For symbol - > addr (for breakpoints)*/
	if (getenv("SYMBOL_MAPPING")) {
		load_symbol_map(getenv("SYMBOL_MAPPING"));
#if defined(HP_BACKEND_BOCHS)
		if (getenv("HACK_TIMER_MOD")) {
			timer_mod[0] = sym_to_addr2("qemu-system", "timer_mod");
			timer_mod[1] = sym_to_addr2("qemu-system", "timer_mod_anticipate");
			timer_mod[2] = sym_to_addr2("qemu-system", "timer_mod_ns");
			timer_mod[3] = sym_to_addr2("qemu-system", "timer_mod_anticipate_ns");
			timer_mod[4] = sym_to_addr2("qemu-system", "qemu_clock_get_ns");
			hack_timer_mod = true;
		}
#endif
	}

	cpu0_tlb_flush();
	fuzz_walk_slat();
	l2_fixup();
	slat_mark_page_table();
	init_register_feedback();

	if (getenv("LINK_MAP") && getenv("LINK_OBJ_REGEX"))
		load_link_map(getenv("LINK_MAP"), getenv("LINK_OBJ_REGEX"),
			      strtoll(getenv("LINK_OBJ_BASE"), NULL, 16));

#if defined(HP_X86_64)
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
#endif
	if (getenv("KVM")) {
#if defined(HP_X86_64)
		add_pc_range(0, 0x7fffffffffff);
#endif
		apply_breakpoints_linux();
    }
#if defined(HP_AARCH64)
	if (getenv("SEL4")) {
		apply_breakpoints_seL4();
	}
#endif

	/*
	 * make a copy of the CPU state, which we use to reset the CPU
	 * state after each fuzzer input
	 */
	save_cpu();

	/* Start tracking accesses to the memory so we can roll-back changes
	 * after each fuzzer input */
	fuzz_watch_memory_inc();
	reset_vm();

	/* Enumerate or Load the cached list of PIO and MMIO Regions */
	fuzzenum = true;
	init_regions(icp_db_path);
	fuzzenum = false;

#if defined(HP_INPUT_GEN_TRUMAN)
	add_interface(INTERFACE_TYPE_DMA, 0, 0x1, "DMA", 0, 0);
#endif

	atexit(cleanup);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGALRM, handle_signal);

	return 0;
}
