/////////////////////////////////////////////////////////////////////////
// $Id$
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2002-2021  The Bochs Project Team
//  Modified by Qiang Liu <cyruscyliu@gmail.com>
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
//
/////////////////////////////////////////////////////////////////////////

#include "fuzz.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netdb.h>
#define closesocket(s)    close(s)

#define NEED_CPU_REG_SHORTCUTS 1

static int last_stop_reason = GDBSTUB_STOP_NO_REASON;

#define GDBSTUB_EXECUTION_BREAKPOINT    (0xac1)
#define GDBSTUB_TRACE                   (0xac2)
#define GDBSTUB_USER_BREAK              (0xac3)

static int listen_socket_fd;
static int socket_fd;

static int hex(char ch)
{
  if ((ch >= 'a') && (ch <= 'f')) return(ch - 'a' + 10);
  if ((ch >= '0') && (ch <= '9')) return(ch - '0');
  if ((ch >= 'A') && (ch <= 'F')) return(ch - 'A' + 10);
  return(-1);
}

static char buf[4096], *bufptr = buf;

static void flush_debug_buffer()
{
  char *p = buf;
  while (p != bufptr) {
    int n = send(socket_fd, p, bufptr-p, 0);
    if (n == -1) {
      verbose_printf("error on debug socket: %m\n");
      break;
    }
    p += n;
  }
  bufptr = buf;
}

static void put_debug_char(char ch)
{
  if (bufptr == buf + sizeof buf)
    flush_debug_buffer();
  *bufptr++ = ch;
}

static char get_debug_char(void)
{
  char ch;

  recv(socket_fd, &ch, 1, 0);

  return(ch);
}

static const char hexchars[]="0123456789abcdef";

static void put_reply(const char* buffer)
{
  unsigned char csum;
  int i;

  verbose_printf("put_buffer '%s'\n", buffer);

  do {
    put_debug_char('$');

    csum = 0;

    i = 0;
    while (buffer[i] != 0)
    {
      put_debug_char(buffer[i]);
      csum = csum + buffer[i];
      i++;
    }

    put_debug_char('#');
    put_debug_char(hexchars[csum >> 4]);
    put_debug_char(hexchars[csum % 16]);
    flush_debug_buffer();
  } while (get_debug_char() != '+');
}

static void get_command(char* buffer)
{
  unsigned char checksum;
  unsigned char xmitcsum;
  char ch;
  unsigned int count;
  unsigned int i;

  do {
    while ((ch = get_debug_char()) != '$');

    checksum = 0;
    xmitcsum = 0;
    count = 0;

    while (1)
    {
      ch = get_debug_char();
      if (ch == '#') break;
      checksum = checksum + ch;
      buffer[count] = ch;
      count++;
    }
    buffer[count] = 0;

    if (ch == '#')
    {
      xmitcsum = hex(get_debug_char()) << 4;
      xmitcsum += hex(get_debug_char());
      if (checksum != xmitcsum)
      {
        verbose_printf("Bad checksum\n");
      }
    }

    if (checksum != xmitcsum)
    {
      put_debug_char('-');
      flush_debug_buffer();
    }
    else
    {
      put_debug_char('+');
      if (buffer[2] == ':')
      {
        put_debug_char(buffer[0]);
        put_debug_char(buffer[1]);
        count = strlen(buffer);
        for (i = 3; i <= count; i++)
        {
          buffer[i - 3] = buffer[i];
        }
      }
      flush_debug_buffer();
    }
  } while (checksum != xmitcsum);
}

void hex2mem(char* buf, unsigned char* mem, int count)
{
  unsigned char ch;

  for (int i = 0; i<count; i++)
  {
    ch = hex(*buf++) << 4;
    ch = ch + hex(*buf++);
    *mem++ = ch;
  }
}

char* mem2hex(const uint8_t* mem, char* buf, int count)
{
  for (int i = 0; i<count; i++)
  {
    uint8_t ch = *mem++;
    *buf++ = hexchars[ch >> 4];
    *buf++ = hexchars[ch % 16];
  }
  *buf = 0;
  return(buf);
}

int hexdigit(char c)
{
  if (isdigit(c))
    return c - '0';
  else if (isupper(c))
    return c - 'A' + 10;
  else
    return c - 'a' + 10;
}

uint64_t read_little_endian_hex(char *&buf)
{
  int byte;
  uint64_t ret = 0;
  int n = 0;
  while (isxdigit(*buf)) {
    byte = hexdigit(*buf++);
    if (isxdigit(*buf))
      byte = (byte << 4) | hexdigit(*buf++);
    ret |= (uint64_t)byte << (n*8);
    ++n;
  }
  return ret;
}

static int continue_thread = -1;
static int other_thread = 0;


#define MAX_BREAKPOINTS (255)
static uint64_t breakpoints[MAX_BREAKPOINTS] = {0,};
static unsigned nr_breakpoints = 0;

struct hp_watchpoint { uint64_t addr; uint8_t len; uint8_t rwa; };
#define MAX_WATCHPOINTS  (16)
static struct hp_watchpoint watchpoints[MAX_WATCHPOINTS] = { {0, 0, 0} };
static unsigned nr_watchpoints = 0;

static int stub_trace_flag = 0;
static int instr_count = 0;
static int saved_rip = 0;
static int bx_enter_gdbstub = 0;

void bx_gdbstub_break(void)
{
  bx_enter_gdbstub = 1;
}

int bx_gdbstub_check(uint64_t eip)
{
  if(!BX_CPU(0)->fuzzdebug_gdb)
      return 0;
  unsigned int i;
  unsigned char ch;
  int r;
  long arg;

  if (bx_enter_gdbstub)
  {
    bx_enter_gdbstub = 0;
    last_stop_reason = GDBSTUB_EXECUTION_BREAKPOINT;
    return GDBSTUB_EXECUTION_BREAKPOINT;
  }

  instr_count++;

  if ((instr_count % 500) == 0)
  {
    arg = fcntl(socket_fd, F_GETFL);
    fcntl(socket_fd, F_SETFL, arg | O_NONBLOCK);
    r = recv(socket_fd, &ch, 1, 0);
    fcntl(socket_fd, F_SETFL, arg);
    if (r == 1)
    {
      verbose_printf("Got byte %u\n", (unsigned int)ch);
      last_stop_reason = GDBSTUB_USER_BREAK;
      return GDBSTUB_USER_BREAK;
    }
  }

  for (i = 0; i < nr_breakpoints; i++)
  {
    if (eip == breakpoints[i])
    {
      verbose_printf("found breakpoint at %lx\n", eip);
      last_stop_reason = GDBSTUB_EXECUTION_BREAKPOINT;
      return GDBSTUB_EXECUTION_BREAKPOINT;
    }
  }

  if (stub_trace_flag == 1)
  {
    last_stop_reason = GDBSTUB_TRACE;
    return GDBSTUB_TRACE;
  }
  last_stop_reason = GDBSTUB_STOP_NO_REASON;
  return GDBSTUB_STOP_NO_REASON;
}

static int remove_breakpoint(uint64_t addr, int len)
{
  if (len != 1)
  {
    return(0);
  }

  for (unsigned i = 0; i < MAX_BREAKPOINTS; i++)
  {
    if (breakpoints[i] == addr)
    {
      verbose_printf("Removing breakpoint at " FMT_ADDRX64, "\n", addr);
      breakpoints[i] = 0;
      return(1);
    }
  }
  return(0);
}

static void insert_breakpoint(uint64_t addr)
{
  unsigned int i;

  verbose_printf("Setting breakpoint at " FMT_ADDRX64, "\n", addr);

  for (i = 0; i < (unsigned)MAX_BREAKPOINTS; i++)
  {
    if (breakpoints[i] == 0)
    {
      breakpoints[i] = addr;
      if (i >= nr_breakpoints)
      {
        nr_breakpoints = i + 1;
      }
      return;
    }
  }
  verbose_printf("No slot for breakpoint\n");
}

static void do_pc_breakpoint(int insert, uint64_t addr, int len)
{
  for (int i = 0; i < len; ++i)
    if (insert)
      insert_breakpoint(addr+i);
    else
      remove_breakpoint(addr+i, 1);
}

#define WATCHPOINT_R 0x01
#define WATCHPOINT_W 0x10
#define WATCHPOINT_A 0x11

static int remove_watchpoint(uint64_t addr) {
  for (unsigned i = 0; i < MAX_WATCHPOINTS; i++) {
    if (watchpoints[i].addr == addr) {
      watchpoints[i].addr = 0;
      verbose_printf("Removed watchpoint at " FMT_ADDRX64, "\n", addr);
      return 1;
    }
  }
  return 0;
}

static int insert_watchpoint(uint64_t addr, uint8_t len, uint8_t rwa) {
  if (addr == 0) {
    verbose_printf("Cannot watch address 0\n");
    return 0;
  }

  for (int i = 0; i < MAX_WATCHPOINTS; i++) {
    if (watchpoints[i].addr == 0) {
      watchpoints[i].addr = addr;
      watchpoints[i].len = len;
      watchpoints[i].rwa = rwa;
      if (i >= nr_watchpoints) {
        nr_watchpoints = i + 1;
      }
      verbose_printf("Set watchpoint at " FMT_ADDRX64, "\n", addr);
      return 1;
    }
  }
  verbose_printf("No slot for watchpoints\n");
  return 0;
}

static int do_pc_watchpoint(int insert,
    uint64_t addr, uint8_t len, uint8_t rwa) {
  if (insert) {
    return insert_watchpoint(addr, len, rwa);
  } else {
    return remove_watchpoint(addr);
  }
}

static void do_breakpoint(int insert, char* buffer)
{
  char* ebuf;
  unsigned long type = strtoul(buffer, &ebuf, 16);
  uint64_t addr = strtoull(ebuf+1, &ebuf, 16);
  unsigned long len = strtoul(ebuf+1, &ebuf, 16);
  switch (type) {
  case 0: // software breakpoint
  case 1: // hardware breakpoint
    do_pc_breakpoint(insert, addr, len);
    put_reply("OK");
    break;
  case 2: // write watch point
    do_pc_watchpoint(insert, addr, len, WATCHPOINT_W);
    put_reply("OK");
    break;
  case 3: // read watch point
    do_pc_watchpoint(insert, addr, len, WATCHPOINT_R);
    put_reply("OK");
    break;
  case 4: // access watch point
    do_pc_watchpoint(insert, addr, len, WATCHPOINT_A);
    put_reply("OK");
    break;
  default:
    put_reply("");
    break;
  }
}

int hp_gdbstub_mem_check(unsigned cpu,
    uint64_t lin, unsigned len, unsigned rw) {
  if (!BX_CPU(0)->fuzzdebug_gdb) {
    return 0;
  }

  uint64_t lin_end = lin + len - 1;
  for (int i = 0; i < nr_watchpoints; i++) {
    if (watchpoints[i].addr == 0)
      continue;
    uint64_t watch_end = watchpoints[i].addr + len - 1;
    if (lin > watch_end || lin_end < watchpoints[i].addr)
      continue;;
    if (watchpoints[i].rwa == WATCHPOINT_A) {
      bx_enter_gdbstub = 1;
      return 1;
    } else if (watchpoints[i].rwa == WATCHPOINT_R && rw == 0) {
      bx_enter_gdbstub = 1;
      return 1;
    } else if (watchpoints[i].rwa == WATCHPOINT_W && rw == 1) {
      bx_enter_gdbstub = 1;
      return 1;
    }
  }
  return 0;
}

static void write_signal(char* buf, int signal)
{
  buf[0] = hexchars[signal >> 4];
  buf[1] = hexchars[signal % 16];
  buf[2] = 0;
}

static int access_linear(uint64_t laddress,
                        unsigned len,
                        unsigned int rw,
                        uint8_t* data)
{
  bx_phy_address phys;
  bool valid;

  if (((laddress & 0xfff) + len) > 4096)
  {
    valid = access_linear(laddress,
                          4096 - (laddress & 0xfff),
                          rw,
                          data);
    if (!valid) return(0);

    valid = access_linear(laddress,
                          len + (laddress & 0xfff) - 4096,
                          rw,
                          (uint8_t *)(data + (4096 - (laddress & 0xfff))));
    return(valid);
  }

  valid = BX_CPU(0)->dbg_xlate_linear2phy(laddress, (bx_phy_address*)&phys);
  if (!valid) return(0);

  if (rw & 1) {
    valid = BX_MEM(0)->dbg_set_mem(BX_CPU(0), phys, len, data);
  } else {
    valid = BX_MEM(0)->dbg_fetch_mem(BX_CPU(0), phys, len, data);
  }

  return(valid);
}

#define RAX (BX_CPU_THIS_PTR gen_reg[0].rrx)
#define RCX (BX_CPU_THIS_PTR gen_reg[1].rrx)
#define RDX (BX_CPU_THIS_PTR gen_reg[2].rrx)
#define RBX (BX_CPU_THIS_PTR gen_reg[3].rrx)
#define RSP (BX_CPU_THIS_PTR gen_reg[4].rrx)
#define RBP (BX_CPU_THIS_PTR gen_reg[5].rrx)
#define RSI (BX_CPU_THIS_PTR gen_reg[6].rrx)
#define RDI (BX_CPU_THIS_PTR gen_reg[7].rrx)
#define R8  (BX_CPU_THIS_PTR gen_reg[8].rrx)
#define R9  (BX_CPU_THIS_PTR gen_reg[9].rrx)
#define R10 (BX_CPU_THIS_PTR gen_reg[10].rrx)
#define R11 (BX_CPU_THIS_PTR gen_reg[11].rrx)
#define R12 (BX_CPU_THIS_PTR gen_reg[12].rrx)
#define R13 (BX_CPU_THIS_PTR gen_reg[13].rrx)
#define R14 (BX_CPU_THIS_PTR gen_reg[14].rrx)
#define R15 (BX_CPU_THIS_PTR gen_reg[15].rrx)

#define RIP (BX_CPU_THIS_PTR gen_reg[BX_64BIT_REG_RIP].rrx)

char last_seen_binary[1024] = { '\0' };

static void debug_loop(void)
{
  char buffer[255];
  char obuf[1024 * 4];
  int ne = 0;
  uint8_t mem[1024 * 4];

  while (ne == 0 && BX_CPU(0)->fuzz_executing_input)
  {
    get_command(buffer);
    verbose_printf("get_buffer '%s'\n", buffer);

    // At a minimum, a stub is required to support the "g" and "G" commands for register access,
    // and the "m" and "M" commands for memory access. Stubs that only control single-threaded
    // targets can implement run control with the "c" (continue), and "s" (step) commands. Stubs
    // that support multi-threading targets should support the "vCont" command. All other commands
    // are optional.

    switch (buffer[0])
    {
      // 'c [addr]' Continue. addr is address to resume.
      // If addr is omitted, resume at current address.
      // This packet is deprecated for multi-threading support. See [vCont packet]
      case 'c':
      {
        char buf[1024];
        uint64_t new_rip;

        if (buffer[1] != 0)
        {
          new_rip = (uint64_t)atoll(buffer + 1);

          verbose_printf("continuing at %lx\n", new_rip);

          BX_CPU(0)->invalidate_prefetch_q();

          saved_rip = BX_CPU(0)->gen_reg[BX_64BIT_REG_RIP].rrx;
          BX_CPU(0)->gen_reg[BX_64BIT_REG_RIP].rrx = new_rip;
        }

        stub_trace_flag = 0;
        BX_CPU(0)->cpu_loop();

        if (buffer[1] != 0)
        {
          BX_CPU(0)->invalidate_prefetch_q();
          BX_CPU(0)->gen_reg[BX_64BIT_REG_RIP].rrx = saved_rip;
        }

        verbose_printf("stopped with %x\n", last_stop_reason);
        buf[0] = 'S';
        if (last_stop_reason == GDBSTUB_EXECUTION_BREAKPOINT ||
            last_stop_reason == GDBSTUB_TRACE)
        {
          write_signal(&buf[1], SIGTRAP);
          auto s = addr_to_sym(RIP);
          const char *current_binary = s.first.c_str();
          if ((strlen(current_binary) > 1) && strncmp(last_seen_binary, current_binary, strlen(current_binary))) {
            memcpy(last_seen_binary, current_binary, strlen(current_binary));
            buf[0] = 'T';
            mem2hex((uint8_t *)current_binary, (char *)mem, strlen(current_binary));
            sprintf(&buf[3], "exec:%s;", mem);
          }
        }
        else
        {
          write_signal(&buf[1], 0);
        }
        put_reply(buf);
        break;
      }

      // 's [addr]' Single step. addr is the address at which to resume.
      // If addr is omitted, resume at same address.
      // This packet is deprecated for multi-threading support. See [vCont packet]
      case 's':
      {
        char buf[1024];

        verbose_printf("stepping\n");
        stub_trace_flag = 1;
        bx_cpu.cpu_loop();
        stub_trace_flag = 0;
        verbose_printf("stopped with %x\n", last_stop_reason);
        buf[0] = 'S';
        if (last_stop_reason == GDBSTUB_EXECUTION_BREAKPOINT ||
            last_stop_reason == GDBSTUB_TRACE)
        {
          write_signal(&buf[1], SIGTRAP);
        }
        else
        {
          write_signal(&buf[1], SIGTRAP);
        }
        auto s = addr_to_sym(RIP);
        const char *current_binary = s.first.c_str();
        if ((strlen(current_binary) > 1) && strncmp(last_seen_binary, current_binary, strlen(current_binary))) {
          memcpy(last_seen_binary, current_binary, strlen(current_binary));
          buf[0] = 'T';
          mem2hex((uint8_t *)current_binary, (char *)mem, strlen(current_binary));
          sprintf(&buf[3], "exec:%s;", mem);
        }
        put_reply(buf);
        break;
      }

      // "M addr,length:XX..."
      // Write length bytes of memory starting at address addr. XX... is the data;
      // each byte is transmitted as a two-digit hexadecimal number.
      case 'M':
      {
        unsigned char mem[255];
        char* ebuf;

        uint64_t addr = strtoull(&buffer[1], &ebuf, 16);
        int len = strtoul(ebuf + 1, &ebuf, 16);
        hex2mem(ebuf + 1, mem, len);

        if (len == 1 && mem[0] == 0xcc)
        {
          insert_breakpoint(addr);
          put_reply("OK");
        }
        else if (remove_breakpoint(addr, len))
        {
          put_reply("OK");
        }
        else
        {
          if (access_linear(addr, len, BX_WRITE, mem))
          {
            put_reply("OK");
          }
          else
          {
            put_reply("Eff");
          }
        }
        break;
      }

      // "m addr,length"
      // Read length bytes of memory starting at address addr. Note that addr may
      // not be aligned to any particular boundary.

      // The stub need not use any particular size or alignment when gathering data
      // from memory for the response; even if addr is word-aligned and length is a
      // multiple of the word size, the stub is free to use byte accesses, or not. For
      // this reason, this packet may not be suitable for accessing memory-mapped I/O
      // devices.
      case 'm':
      {
        uint64_t addr;
        int len;
        char* ebuf;

        addr = strtoull(&buffer[1], &ebuf, 16);
        len = strtoul(ebuf + 1, NULL, 16);
        verbose_printf("addr " FMT_ADDRX64 " len %x\n", addr, len);

        access_linear(addr, len, BX_READ, mem);
        mem2hex(mem, obuf, len);
        put_reply(obuf);
        break;
      }

      // "P n...=r..."
      // Write register n... with value r... The register number n is in hexadecimal,
      // and r... contains two hex digits for each byte in the register (target byte order).
      case 'P':
      {
        int reg;
        uint64_t value;
        char* ebuf;

        reg = strtoul(&buffer[1], &ebuf, 16);
        ++ebuf;
        value = read_little_endian_hex(ebuf);

        verbose_printf("reg %d set to " FMT_ADDRX64, "\n", reg, value);
        switch (reg)
        {
          case 0:
          case 1:
          case 2:
          case 3:
          case 4:
          case 5:
          case 6:
          case 7:
          case 8:
          case 9:
          case 10:
          case 11:
          case 12:
          case 13:
          case 14:
          case 15:
            BX_CPU_THIS_PTR set_reg64(reg, value);
            break;

          case 16:
            RIP = value;
            BX_CPU_THIS_PTR invalidate_prefetch_q();
            break;

          default:
            break;
        }
        put_reply("OK");

        break;
      }

      // "g" Read general registers.
      case 'g':
      {
#define PUTREG(buf, val, len) do { \
         uint64_t u = (val); \
         (buf) = mem2hex((const uint8_t*)&u, (buf), (len)); \
      } while (0)
        char* buf = obuf;
        PUTREG(buf, RAX, 8);
        PUTREG(buf, RBX, 8);
        PUTREG(buf, RCX, 8);
        PUTREG(buf, RDX, 8);
        PUTREG(buf, RSI, 8);
        PUTREG(buf, RDI, 8);
        PUTREG(buf, RBP, 8);
        PUTREG(buf, RSP, 8);
        PUTREG(buf, R8,  8);
        PUTREG(buf, R9,  8);
        PUTREG(buf, R10, 8);
        PUTREG(buf, R11, 8);
        PUTREG(buf, R12, 8);
        PUTREG(buf, R13, 8);
        PUTREG(buf, R14, 8);
        PUTREG(buf, R15, 8);
        uint64_t rip;
        rip = RIP;
        if (last_stop_reason == GDBSTUB_EXECUTION_BREAKPOINT)
        {
          ++rip;
        }
        PUTREG(buf, rip, 8);
        PUTREG(buf, BX_CPU_THIS_PTR read_eflags(), 4);
        PUTREG(buf, BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value, 4);
        PUTREG(buf, BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].selector.value, 4);
        PUTREG(buf, BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].selector.value, 4);
        PUTREG(buf, BX_CPU_THIS_PTR sregs[BX_SEG_REG_ES].selector.value, 4);
        PUTREG(buf, BX_CPU_THIS_PTR sregs[BX_SEG_REG_FS].selector.value, 4);
        PUTREG(buf, BX_CPU_THIS_PTR sregs[BX_SEG_REG_GS].selector.value, 4);
        put_reply(obuf);
        break;
      }

      case '?':
        sprintf(obuf, "S%02x", SIGTRAP);
        put_reply(obuf);
        break;

      // "H op thread-id"
      // Set thread for subsequent operations ("m", "M", "g", "G", et.al.). op depends on the
      // operation to be performed: it should be "c" for step and continue operations
      // (note that this is deprecated, supporting the "vCont" command is a better option),
      // "g" for other operations. The thread designator thread-id has the format
      // and interpretation described in [thread-id syntax]
      case 'H':
        if (buffer[1] == 'c')
        {
          continue_thread = strtol(&buffer[2], NULL, 16);
          put_reply("OK");
        }
        else if (buffer[1] == 'g')
        {
          other_thread = strtol(&buffer[2], NULL, 16);
          put_reply("OK");
        }
        else
        {
          put_reply("Eff");
        }
        break;

      // "q name params..."
      // "Q name params..."
      // General query ("q") and set ("Q"). These packets are described fully in
      // Section E.4 [General Query Packets]
      case 'q':
        if (buffer[1] == 'C')
        {
          sprintf(obuf, FMT_ADDRX64, (uint64_t)1);
          put_reply(obuf);
        }
        else if (strncmp(&buffer[1], "Offsets", strlen("Offsets")) == 0)
        {
          if (getenv("LINK_OBJ_BASE")) {
            uint64_t base = strtoull(getenv("LINK_OBJ_BASE"), NULL, 16);
            sprintf(obuf, "Text=%lx;Data=%lx;Bss=%lx", base, base, base);
            put_reply(obuf);
          } else {
            put_reply("");
          }
        }
        else if (strncmp(&buffer[1], "Supported", strlen("Supported")) == 0)
        {
          put_reply("PacketSize=4000;qXfer:exec-file:read+");
        }
        // qRcmd,command
        else if (strncmp(&buffer[1], "Rcmd", strlen("Rcmd")) == 0)
        {
          hex2mem(&buffer[6], mem, 8);
          if (strncmp((char *)mem, "info mem", 8) == 0) {
              put_reply("OK");
          } else {
            verbose_printf("not supported\n");
            put_reply(""); /* not supported */
          }
        }
        // qXfer:exec-file:read:annex:offset,length
        else if (strncmp(&buffer[1], "Xfer:exec-file:read::", strlen("Xfer:exec-file:read::")) == 0)
        {
          auto s = addr_to_sym(RIP);
          const char *current_binary = s.first.c_str();
          sprintf(obuf, "l%s", current_binary);
          memcpy(last_seen_binary, current_binary, strlen(current_binary));
          put_reply(obuf);
        }
        // qAttached
        else if (strncmp(&buffer[1], "Attached", strlen("Attached")) == 0)
        {
          put_reply("1");
        }
        // qSymbol::
        else if (strncmp(&buffer[1], "Symbol::", strlen("Symbol::")) == 0)
        {
          put_reply("OK");
        }
        else
        {
          verbose_printf("not supported\n");
          put_reply(""); /* not supported */
        }
        break;

      // "z type,addr,kind"
      // "Z type,addr,kind"
      // Insert ("Z") or remove ("z") a type breakpoint or watchpoint starting at address
      // address of kind kind.
      case 'Z':
        do_breakpoint(1, buffer+1);
        break;
      case 'z':
        do_breakpoint(0, buffer+1);
        break;

      // "k" Kill request.
      case 'k':
        printf("Debugger asked us to quit\n");
        cpu0_set_fuzz_executing_input(false);
        break;

      case 'D':
        printf("Debugger detached\n");
        put_reply("OK");
        return;
        break;

      default:
        put_reply("");
        break;
    }
  }
}

static void wait_for_connect(int portn)
{
  struct sockaddr_in sockaddr;
  socklen_t sockaddr_len;
  struct protoent *protoent;
  int r;
  int opt;

  listen_socket_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (listen_socket_fd == -1)
  {
    printf("Failed to create socket");
    exit(1);
  }

  /* Allow rapid reuse of this port */
  opt = 1;
  r = setsockopt(listen_socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  if (r == -1)
  {
    verbose_printf("setsockopt(SO_REUSEADDR) failed\n");
  }

  memset (&sockaddr, '\000', sizeof sockaddr);
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(portn);
  sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

  r = bind(listen_socket_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
  if (r == -1)
  {
    verbose_printf("Failed to bind socket\n");
  }

  r = listen(listen_socket_fd, 0);
  if (r == -1)
  {
    verbose_printf("Failed to listen on socket\n");
  }

  sockaddr_len = sizeof sockaddr;
  socket_fd = accept(listen_socket_fd, (struct sockaddr *)&sockaddr, &sockaddr_len);
  if (socket_fd == -1)
  {
    verbose_printf("Failed to accept on socket\n");
  }
  closesocket(listen_socket_fd);

  protoent = getprotobyname("tcp");
  if (!protoent)
  {
    verbose_printf("getprotobyname (\"tcp\") failed\n");
    return;
  }

  /* Disable Nagle - allow small packets to be sent without delay. */
  opt = 1;
  r = setsockopt(socket_fd, protoent->p_proto, TCP_NODELAY, &opt, sizeof(opt));
  if (r == -1)
  {
    verbose_printf("setsockopt(TCP_NODELAY) failed\n");
  }
  uint32_t ip = sockaddr.sin_addr.s_addr;
  verbose_printf("Connected to %d.%d.%d.%d\n", ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff);
}

void hp_gdbstub_debug_loop(void)
{
  int portn = 1234;

  /* Wait for connect */
  printf("Waiting for gdb connection on port %d\n", portn);
  wait_for_connect(portn);

  /* Do debugger command loop */
  debug_loop();

  closesocket(socket_fd);
}
