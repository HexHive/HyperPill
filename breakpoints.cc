#include "fuzz.h"
#include <tsl/robin_map.h>
#include <utility>
#include <vector>

/*
 * List of capabilities we want:
 *      Skip a function call. (+ set return value)
 *      Take a jump (even if we don't want to).
 *      Teleport the PC.
 *      Should be based primarily on symbol names
 *      Hook Syscalls
 *
 *  Design. Apis:
 *      PC Hook.
 *      Instruction Hook.
 *      Ctrl-xfer hook?
 *
 *  Call hook sideffects:
 *      Skip the call.
 *      Change the call destination.
 *      Change the call return
 */


/*
 * These breakpoints need to be pretty fast
 */
#define MAX_BPS 16
using breakpoint_handler_t = void (*)(bxInstruction_c *);
std::pair<bx_address, breakpoint_handler_t> breakpoints[MAX_BPS]; 
static unsigned int bp_index;

bx_address min_bp = -1;
bx_address max_bp;



void handle_breakpoints(bxInstruction_c *insn) {
    auto rip = BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx;
    if(rip < min_bp || rip > max_bp)
        return;
    for (unsigned int i =0; i<bp_index; i++){
        if(breakpoints[i].first  == rip)
            breakpoints[i].second(insn);
    }
}

bx_address add_breakpoint(bx_address addr, const breakpoint_handler_t h) {
    if(!addr)
        return addr;
    assert(bp_index < MAX_BPS);
    addr_bin_name addr_bin_name;
    addr_bin_name.addr = addr;
    addr_to_sym(&addr_bin_name);
    printf("Applying breakpoint to: %lx %s\n", addr, addr_bin_name.name);
    breakpoints[bp_index++] = std::make_pair(addr, h);
    if(addr > max_bp)
        max_bp = addr;
    if(addr< min_bp)
        min_bp = addr;
    return addr;
}

static char* copy_string_from_vm(bx_address addr, size_t len) {
    len = len&0xFFF;
    char *buf = (char*)malloc(len);
    BX_CPU(0)->access_read_linear(addr, len, 3, BX_READ, 0x0, buf);
    buf[len-1] = 0;
    return buf;
}

static void bp__stdio_write(bxInstruction_c *i){
    i->execute1 = BX_CPU_C::RETnear64_Iw;
    i->modRMForm.Iw[0] = 0;
    i->modRMForm.Iw[1] = 0;
    BX_CPU(id)->gen_reg[BX_64BIT_REG_RAX].rrx = 0;
    BX_CPU(id)->async_event = 1;

    char* msg = copy_string_from_vm(BX_CPU(id)->gen_reg[BX_64BIT_REG_RSI].rrx,
            BX_CPU(id)->gen_reg[BX_64BIT_REG_RDX].rrx);
    printf("__stdio_write: %s\n", msg);
    free(msg);
}

void apply_breakpoints_linux() {
    // sanitizer stuff
    // _asan_report_store4
    // -> __asan::ReportGenericError or __asan::ReportDoubleFree()
    //     -> __asan::ScopedInErrorReport::ScopedInErrorReport()
    //     -> __asan::ErrorGeneric::ErrorGeneric
    //     -> internal_memcpy(&current_error_, &description, sizeof(current_error_));
    //     -> __asan::ScopedInErrorReport::~ScopedInErrorReport()
    //         -> __asan::DescribeThread()
    //         -> __sanitizer::Die(), abort or exit
    add_breakpoint(sym_to_addr2("firecracker", "core::panicking::panic_fmt"), [](bxInstruction_c *i) {
            fuzz_emu_stop_crash("firecracker: panic");
            });
    add_breakpoint(sym_to_addr2("vmm", "pthread_rwlock_rdlock"), [](bxInstruction_c *i) {
            i->execute1 = BX_CPU_C::RETnear64_Iw;
            i->modRMForm.Iw[0] = 0;
            i->modRMForm.Iw[1] = 0;
            BX_CPU(id)->gen_reg[BX_64BIT_REG_RAX].rrx = 0;
            BX_CPU(id)->async_event = 1;
            });
    add_breakpoint(sym_to_addr2("vmm", "pthread_rwlock_unlock"), [](bxInstruction_c *i) {
            i->execute1 = BX_CPU_C::RETnear64_Iw;
            i->modRMForm.Iw[0] = 0;
            i->modRMForm.Iw[1] = 0;
            BX_CPU(id)->gen_reg[BX_64BIT_REG_RAX].rrx = 0;
            BX_CPU(id)->async_event = 1;
            });
    add_breakpoint(sym_to_addr2("firecracker", "__asan::CheckUnwind()"), [](bxInstruction_c *i) {
            printf("Skipping __asan::CheckUnwind");
            print_stacktrace();
            i->execute1 = BX_CPU_C::RETnear64_Iw;
            i->modRMForm.Iw[0] = 0;
            i->modRMForm.Iw[1] = 0;
            BX_CPU(id)->async_event = 1;
            });
    add_breakpoint(sym_to_addr2("libasan.so", "__asan::ScopedInErrorReport::~ScopedInErrorReport"), [](bxInstruction_c *i) {
            // every error through asan should reach this
            printf("ASAN error report\n");
            fuzz_stacktrace();
            });
    add_breakpoint(sym_to_addr2("libc.so", "abort@@GLIBC_2.2.5"), [](bxInstruction_c *i) {
            fuzz_emu_stop_crash("abort");
    });

    add_breakpoint(sym_to_addr2("vmm", "__stdio_write"), bp__stdio_write);
    add_breakpoint(sym_to_addr2("ld-musl", "__stdio_write"), bp__stdio_write);
    //add_breakpoint(sym_to_addr2("ld-musl", "out"), bp__stdio_write);
    add_breakpoint(sym_to_addr2("vmlinux", "crash_kexec"), [](bxInstruction_c *i) {
            printf("kexec crash\n");
            print_stacktrace();
    });
    add_breakpoint(sym_to_addr2("vmlinux", "qi_flush_iec"), [](bxInstruction_c *i) {
            i->execute1 = BX_CPU_C::RETnear64_Iw;
            i->modRMForm.Iw[0] = 0;
            i->modRMForm.Iw[1] = 0;
            BX_CPU(id)->gen_reg[BX_64BIT_REG_RAX].rrx = 0;
            BX_CPU(id)->async_event = 1;
    });
}


void handle_syscall_hooks(bxInstruction_c *i)
{
    // crashes often go for exit/abort
    /* Hook Syscalls */
    if (i->getIaOpcode() == 0x471) {
        switch(BX_CPU(id)->gen_reg[BX_64BIT_REG_RAX].rrx) {
            case 231:
            case 60:    // exit
                fuzz_emu_stop_crash("exit syscall");
                return;
                break;
            case 62:    // kill
            case 200:   // tkill
                if (BX_CPU(id)->gen_reg[BX_64BIT_REG_RSI].rrx == 6) { // SIGABRT
                    fuzz_emu_stop_crash("kill syscall");
                    return;
                }
                break;
            case 1:     // write
                if (BX_CPU(id)->gen_reg[BX_64BIT_REG_RDI].rrx == 1 ||
                        BX_CPU(id)->gen_reg[BX_64BIT_REG_RDI].rrx == 2) {
                    i->execute1 = BX_CPU_C::NOP;
                    size_t len = BX_CPU(id)
                        ->gen_reg[BX_64BIT_REG_RDX]
                        .rrx &
                        0xFFF;
                    char *buf = (char *)malloc(len + 1);
                    BX_CPU(0)->access_read_linear(
                            BX_CPU(id)
                            ->gen_reg[BX_64BIT_REG_RSI]
                            .rrx,
                            len, 3, BX_READ, 0x0, buf);
                    buf[len] = 0;
                    printf("write: %s\n", buf);
                    BX_CPU(id)->gen_reg[BX_64BIT_REG_RAX].rrx = len;
                    return;
                }
                break;
        }
    }
}
