#ifndef HYPERPILL_QEMU_H
#define HYPERPILL_QEMU_H

//#include "qemu/osdep.h"
// #include "sysemu/sysemu.h"
extern "C" void qemu_init(int argc, char **argv);
extern "C" int qemu_main_loop(void);
extern "C" void qemu_cleanup(int);

#endif