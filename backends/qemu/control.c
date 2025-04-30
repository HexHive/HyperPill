#include "qemu.h"

ARMCPU shadow_qemu_cpu;

bool cpu0_get_fuzztrace(void) {
    return QEMU_CPU(0)->fuzztrace;
}

void cpu0_set_fuzztrace(bool fuzztrace) {
    QEMU_CPU(0)->fuzztrace = fuzztrace;
}

void cpu0_set_fuzz_executing_input(bool fuzzing) {
    QEMU_CPU(0)->fuzz_executing_input = fuzzing;
}

bool cpu0_get_fuzz_executing_input(void) {
    return QEMU_CPU(0)->fuzz_executing_input;
}

void el_change_fn(ARMCPU *cpu, void *opaque) {
}

/* Copied from QEMU 8.2.0, target/arm/tcg/helper-a64.c */
int el_from_spsr(uint32_t spsr)
{
    /* Return the exception level that this SPSR is requesting a return to,
     * or -1 if it is invalid (an illegal return)
     */
    if (spsr & PSTATE_nRW) {
        switch (spsr & CPSR_M) {
        case ARM_CPU_MODE_USR:
            return 0;
        case ARM_CPU_MODE_HYP:
            return 2;
        case ARM_CPU_MODE_FIQ:
        case ARM_CPU_MODE_IRQ:
        case ARM_CPU_MODE_SVC:
        case ARM_CPU_MODE_ABT:
        case ARM_CPU_MODE_UND:
        case ARM_CPU_MODE_SYS:
            return 1;
        case ARM_CPU_MODE_MON:
            /* Returning to Mon from AArch64 is never possible,
             * so this is an illegal return.
             */
        default:
            return -1;
        }
    } else {
        if (extract32(spsr, 1, 1)) {
            /* Return with reserved M[1] bit set */
            return -1;
        }
        if (extract32(spsr, 0, 4) == 1) {
            /* return to EL0 with M[0] bit set */
            return -1;
        }
        return extract32(spsr, 2, 2);
    }
}

void pre_el_change_fn(ARMCPU *cpu, void *opaque) {
	CPUARMState *env = &cpu->env;
    CPUState *cs = env_cpu(env);

    unsigned int cur_el = arm_current_el(env);

    /* If we exit the hypervisor...
     *
     * NOTE: checking cur_el = 2, new_el = 1 should only work on hardware
     * providing ARM VHE and hypervisor making use of VHE mode.
     * Without ARM VHE, a hosted hypervisor would work in split mode, with a
     * stub that catches all traps to EL2 and redirects control flow to EL1
     * where the hypervisor actually sits. In that case, we would need more
     * checks to differentiate whether we are returning control to the
     * guest OS or the host OS/hypervisor running in EL1.
     */
    if (cur_el == 2) {
        unsigned int spsr_idx = aarch64_banked_spsr_index(cur_el);
        uint32_t spsr = env->banked_spsr[spsr_idx];
        unsigned int new_el = el_from_spsr(spsr);

        if (new_el == 1) {
            fuzz_hook_back_to_el1_kernel();
        }
    }
}

void before_exec_tb_fn(int cpu_index, TranslationBlock *tb) {
    if(tb == NULL || QEMU_CPU(0)->cpu_index != cpu_index)
        return;

    qemu_tb_before_execution(NULL);
}

void after_exec_tb_fn(int cpu_index, TranslationBlock *tb) {
    static uint64_t prev_pc = 0;

    if(tb == NULL || QEMU_CPU(0)->cpu_index != cpu_index)
        return;

    // printf("TB executed: cpu_index=%d pc=0x%"PRIxPTR" pc_end=0x%"PRIxPTR "\n",
    //    cpu_index, tb->pc, tb->pc_last);

    if (prev_pc == 0) {
        prev_pc = tb->pc;
        return;
    }

    qemu_ctrl_flow_insn(prev_pc, tb->pc);
    prev_pc = tb->pc;
    qemu_tb_after_execution(NULL);
    write_pcs_execution(tb->pc, tb->pc_last);
}

typedef struct {
    uint64_t addr;
} InsnData;

enum Sizes { Byte, Word, Long, Quad, end_sizes };
static void hp_vcpu_mem_access(
        unsigned int cpu_index, qemu_plugin_meminfo_t meminfo,
        uint64_t vaddr, void *userdata, enum qemu_plugin_pos pos, uint32_t size) {
    if (pos == QEMU_PLUGIN_UNKNOW_POS) {
        abort();
    }
    if (pos == QEMU_PLUGIN_AFTER) {
        return;
    }
    if (QEMU_CPU(0)->cpu_index != cpu_index) {
        return;
    }

    struct qemu_plugin_hwaddr *hwaddr;
    hwaddr = qemu_plugin_get_hwaddr(meminfo, vaddr);
    if (hwaddr && qemu_plugin_hwaddr_is_io(hwaddr)) {
        return;
    }

    enum qemu_plugin_mem_rw rw;
    rw = qemu_plugin_mem_is_store(meminfo);

    if (hwaddr) {
        uint64_t addr = qemu_plugin_hwaddr_phys_addr(hwaddr);
        const char *name = qemu_plugin_hwaddr_device_name(hwaddr);
        if (strncmp("RAM", name, strlen("RAM")) != 0) {
            return;
        }
        size_t __size = 0;
        switch (size) {
            case Byte: __size = 1; break;
            case Word: __size = 2; break;
            case Long: __size = 4; break;
            case Quad: __size = 8; break;
            case end_sizes: __size = 16; break;
            default: abort();
        }
        uint8_t data[__size];
        // printf("load, 0x%08"PRIx64", %lx\n", addr, size);
        // if (is_l2_page_bitmap[hwaddr >> 12]) {
        if (0) {
             if (cpu0_get_fuzztrace()) {
                 /* printf(".dma inject: %lx +%lx ",phy, len); */
             }
             fuzz_dma_read_cb(hwaddr->phys_addr, __size, data);
         }
        // __cpu0_mem_write_physical_page(hwaddr->phys_addr, __size, data);
    }
}

static void hp_vcpu_insn_exec(unsigned int cpu_index, void *userdata) {
    // printf("hp_vcpu_insn_exec\n");
}

static void hp_vcpu_tb_exec(unsigned int cpu_index, void *userdata) {
    // printf("hp_vcpu_tb_exec\n");
}

// a plugin solution
static void hp_vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    // printf("hp_vcpu_tb_trans\n");
    size_t n = qemu_plugin_tb_n_insns(tb);
    size_t i;
    InsnData *data;

    for (i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

        qemu_plugin_register_vcpu_mem_cb(
            insn, hp_vcpu_mem_access, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, NULL);

        // find svc (syscall)
        uint32_t insn_opcode = *((uint32_t *)qemu_plugin_insn_data(insn));
        if (!(extract32(insn_opcode, 0, 5) == 0x1 && extract32(insn_opcode, 21, 11) == 0x6a0)) {
            continue;
        }
        // qemu_plugin_register_vcpu_insn_exec_cb(
            // insn, hp_vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);
    }
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, hp_vcpu_tb_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);
}

int hp_qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info) {
    qemu_plugin_register_vcpu_tb_trans_cb(id, hp_vcpu_tb_trans);
    return 0;
}

extern struct qemu_plugin_state plugin;
int hp_qemu_plugin_load() {
    struct qemu_plugin_ctx *ctx;
    int rc;

    ctx = malloc(sizeof(*ctx));
    memset(ctx, 0, sizeof(*ctx));
    ctx->desc = NULL;

    qemu_rec_mutex_lock(&plugin.lock);

    /* find an unused random id with &ctx as the seed */
    ctx->id = (uint64_t)(uintptr_t)ctx;
    for (;;) {
        void *existing;

        ctx->id = rand();
        existing = g_hash_table_lookup(plugin.id_ht, &ctx->id);
        if (likely(existing == NULL)) {
            bool success;

            success = g_hash_table_insert(plugin.id_ht, &ctx->id, &ctx->id);
            g_assert(success);
            break;
        }
    }
    QTAILQ_INSERT_TAIL(&plugin.ctxs, ctx, entry);
    ctx->installing = true;
    rc = hp_qemu_plugin_install(ctx->id, NULL); // always 0
    ctx->installing = false;
    if (rc) {
        // ignored ...
    }

    qemu_rec_mutex_unlock(&plugin.lock);
    return rc;
}

void cpu0_run_loop() {
    vm_start();
    if (qemu_mutex_iothread_locked()) {
        qemu_mutex_unlock_iothread();
    }

    while (cpu0_get_fuzz_executing_input()) {}

    qemu_mutex_lock_iothread();
    vm_stop(RUN_STATE_RESTORE_VM);
}
