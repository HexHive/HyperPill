#include "bochs.h"
#include "pc_system.h"
#include "iodev/iodev.h"
#include "gui/gui.h"

bool bx_user_quit;

#if BX_ENABLE_STATISTICS
void print_statistics_tree(bx_param_c *node, int level) {}
#endif

bx_pc_system_c bx_pc_system;

void bx_init_pc_system() {
    bx_pc_system.initialize(95000000);
    bx_pc_system.register_state();
    bx_pc_system.Reset(BX_RESET_HARDWARE);
    bx_pc_system.start_timers();
}