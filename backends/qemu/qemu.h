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
#include "gdbstub/internals.h"

#include "hw/registerfields.h"
/* <qemu>/target/arm/ */
#include "cpu.h"
#include "internals.h"

#include "accel/tcg/internal-target.h"

#include "qemu/qemu-plugin.h"
#include "qemu/plugin-memory.h"
#include "plugin.h"

typedef uint64_t hp_address;
typedef uint64_t hp_phy_address;
typedef void hp_instruction;

extern CPUState cpu0;
extern CPUState shadow_cpu0;
#define QEMU_CPU(x) (&cpu0)

extern QemuMutex barrier_mutex;
extern QemuCond barrier_cond;
bool qemu_reload_vm(char *tag);

/* AARCH64 cpu related functions */
void aarch64_set_xregs(uint64_t xregs[32]);

typedef enum aa64_syndrom {
    HVC = 0,
    RW,
} aa64_syndrom;

#include "qemuapi.h"

#ifdef __cplusplus
}
#endif

#endif
