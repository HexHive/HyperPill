#ifndef HYPERPILL_QEMU_H
#define HYPERPILL_QEMU_H

#ifdef __cplusplus
extern "C" {
#endif

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/thread.h"
#include "migration/snapshot.h"
#include "qapi/error.h"
#include "sysemu/sysemu.h"
#include "sysemu/runstate.h"
#include "sysemu/cpus.h"
#include "exec/hwaddr.h"
#include "exec/gdbstub.h"
#include "exec/ramblock.h"
#include "gdbstub/internals.h"

#include "hw/registerfields.h"
/* <qemu>/target/arm/ */
#include "cpu.h"
#include "internals.h"

#include "accel/tcg/internal-target.h"

#include "qemu/plugin.h"
#include "qemu/qemu-plugin.h"
#include "qemu/plugin-memory.h"
#include "plugin.h"

typedef uint64_t hp_address;
typedef uint64_t hp_phy_address;
typedef void hp_instruction;

#define QEMU_CPU(x) first_cpu

int hp_qemu_plugin_load();
extern struct qemu_plugin_state plugin;
void hp_vcpu_mem_access(unsigned int cpu_index, qemu_plugin_meminfo_t meminfo,
			uint64_t vaddr, void *userdata,
			enum qemu_plugin_pos pos, uint32_t size);

void el_change_fn(ARMCPU *cpu, void *opaque);
void pre_el_change_fn(ARMCPU *cpu, void *opaque);
void before_exec_tb_fn(int cpu_index, TranslationBlock *tb);
void after_exec_tb_fn(int cpu_index, TranslationBlock *tb);

#define GENMASK(h, l) (((~_UL(0)) << (l)) & (~_UL(0) >> (64 - 1 - (h))))
#define GENMASK_ULL(h, l) (((~_ULL(0)) << (l)) & (~_ULL(0) >> (64 - 1 - (h))))

#ifdef __cplusplus
}
#endif

#include "fuzzc.h"

#endif
