#include "qemu.h"

// #include <unordered_set>

// #include <cstdio>
// #include <cstdint>

// /* File of PCs covered */
// FILE *file_pcs_covered = NULL;
// std::unordered_set<uint64_t> pcs_covered;

void write_pcs_execution(uint64_t pc, uint64_t pc_last) {
//     /* Init PC file */
//     if (file_pcs_covered == NULL) {
//         file_pcs_covered = fopen("pcs_covered.txt", "w");
//         if (file_pcs_covered == NULL) {
//             perror("Could not open coverage file\n");
//             exit(1);
//         }
//     }

//     size_t num_instr = ((pc_last - pc) / 4) + 1; // We assume 32 bit ARM instructions

//     for(size_t i = 0; i < num_instr; i++) {
//         uint64_t curr_pc = pc + (i*4);
//         if (pcs_covered.find(curr_pc) == pcs_covered.end()) {
//             pcs_covered.insert(curr_pc);
//             fprintf(file_pcs_covered, "%016lX\n", curr_pc); // We assume 32 bit ARM instructions
//         }
//     }

//     fflush(file_pcs_covered);
}

void qemu_ctrl_flow_insn(uint64_t branch_pc, uint64_t new_pc) {
    add_edge(branch_pc, new_pc);
    add_stacktrace(branch_pc, new_pc);
}

// void qemu_tb_hlt(unsigned cpu) {
//     fuzz_hook_hlt();
// }

// void qemu_tb_exception(unsigned cpu, unsigned vector, unsigned error_code) {
//     fuzz_hook_exception(vector, error_code);
// }

// void qemu_tb_interrupt(unsigned cpu, unsigned vector) {
//     fuzz_interrupt(cpu, vector);
// }

void qemu_tb_before_execution(TranslationBlock *tb) {
    fuzz_before_execution(tb->icount);
}

void before_exec_tb_fn(int cpu_index, TranslationBlock *tb) {
    if(tb == NULL)
        return;
    qemu_tb_before_execution(tb);
}

void qemu_tb_after_execution(TranslationBlock *tb) {

}

void after_exec_tb_fn(int cpu_index, TranslationBlock *tb) {
    static uint64_t prev_pc = 0;

    if(tb == NULL || QEMU_CPU(0)->cpu_index != cpu_index)
        return;

    prev_pc = tb->pc;
    qemu_ctrl_flow_insn(prev_pc, tb->pc);
    qemu_tb_after_execution(tb);
    write_pcs_execution(tb->pc, tb->pc_last);
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
            // this will send a request
            vm_stop(RUN_STATE_RESTORE_VM);
        }
    }
}

typedef struct {
    uint64_t addr;
} InsnData;

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

        // TODO: not memory access are hooked
        qemu_plugin_register_vcpu_mem_cb(
            insn, hp_vcpu_mem_access, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, NULL);

        // find svc (syscall)
        // https://developer.arm.com/documentation/ddi0602/2022-06/Base-Instructions/SVC--Supervisor-Call-
        // uint32_t insn_opcode = *((uint32_t *)qemu_plugin_insn_data(insn));
        // if ((extract32(insn_opcode, 0, 5) == 0x1) && (extract32(insn_opcode, 21, 11) == 0x6a0)) {
        //     continue;
        // }
    }
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, hp_vcpu_tb_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);
}

int hp_qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info) {
    qemu_plugin_register_vcpu_tb_trans_cb(id, hp_vcpu_tb_trans);
    return 0;
}

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
