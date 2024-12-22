#ifndef HYPERPILL_QEMU_H
#define HYPERPILL_QEMU_H

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/thread.h"
#include "migration/snapshot.h"
#include "qapi/error.h"
#include "sysemu/sysemu.h"
#include "sysemu/runstate.h"
#include "sysemu/cpus.h"
#include "exec/hwaddr.h"

#include "hw/registerfields.h"
/* <qemu>/target/arm/ */
#include "cpu.h"
#include "internals.h"

/* <qemu>/accel/tcg/ */
#include "internal-target.h"

#endif