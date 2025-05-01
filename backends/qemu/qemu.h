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

#include "qemu/qemu-plugin.h"
#include "qemu/plugin-memory.h"
#include "plugin.h"

typedef uint64_t hp_address;
typedef uint64_t hp_phy_address;
typedef void hp_instruction;

extern ARMCPU shadow_qemu_cpu;
#define QEMU_CPU(x) first_cpu

typedef enum aa64_syndrom {
    HVC = 0,
    RW,
} aa64_syndrom;

#ifdef __cplusplus
}
#endif

#include "fuzzc.h"

#endif
