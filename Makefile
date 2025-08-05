NPROCS     := 1
OS         := $(shell uname -s)
ARCH       ?= x86_64
BACKEND    ?= bochs
ifeq ($(ARCH), x86_64)
BACKEND     = bochs
BACKEND_FLAG= -DHP_BACKEND_BOCHS
endif
ifeq ($(BACKEND), bochs)
ARCH        = x86_64
endif

ifeq ($(OS), Linux)
NPROCS     := $(shell grep -c ^processor /proc/cpuinfo)
endif

CC         ?= clang
CXX        ?= clang++

LDFLAGS     = -fPIE -lrt -ldl -lpthread -lsqlite3 -lstdc++fs -lcrypto #-fsanitize=address
ifeq ($(BACKEND), bochs)
INCLUDES    = -I. \
			  -I vendor/bochs \
			  -I vendor/bochs/gui \
			  -I vendor/include \
			  -I vendor/robin-map/include
ARCH_FLAGS  = -DHP_X86_64
else
    $(error Unsupported backend: $(BACKEND))
endif
CFLAGS      = $(INCLUDES) $(ARCH_FLAGS) $(BACKEND_FLAG) -O3 -g -lsqlite3 -fPIE #-stdlib=libc++ -fsanitize=address
CXXFLAGS    =-stdlib=libc++

OBJS_GENERIC= \
			  conveyor.o \
			  cov.o \
			  db.o \
			  fuzz.o \
			  enum.o \
			  feedback.o \
			  link_map.o \
			  main.o \
			  hmem.o \
			  slat.o \
			  sourcecov.o \
			  sym2addr_linux.o \
			  symbolize.o \
			  gdbstub.o

ifeq ($(BACKEND), bochs)
VENDOR_LIBS = vendor/lib/libdebug.a vendor/lib/libcpu.a vendor/lib/libcpudb.a \
			  vendor/lib/libavx.a vendor/lib/libfpu.a \
			  vendor/libfuzzer-ng/libFuzzer.a vendor/lib/pc_system.o
VENDOR_OBJS =
OBJS        = $(OBJS_GENERIC) \
			  backends/bochs/breakpoints.o \
			  backends/bochs/devices.o \
			  backends/bochs/ept.o \
			  backends/bochs/control.o \
			  backends/bochs/init.o \
			  backends/bochs/instrument.o \
			  backends/bochs/mem.o \
			  backends/bochs/regs.o \
			  backends/bochs/vmcs.o \
              backends/bochs/logfunctions.o \
			  backends/bochs/system.o \
              backends/bochs/siminterface.o \
			  backends/bochs/paramtree.o \
			  backends/bochs/gui.o \
			  backends/bochs/apic.o \
              backends/bochs/dbg.o
else
    $(error Unsupported backend: $(BACKEND))
endif

all: rebuild_emulator $(OBJS) $(VENDOR_LIBS) vendor/libfuzzer-ng/libFuzzer.a
ifeq ($(ARCH), x86_64)
	$(CXX) $(CFLAGS) $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) -o fuzz
else
    $(error Unsupported architecture: $(ARCH))
endif

%.o: %.cc $(DEPS)
	$(CXX) $(CFLAGS) $(LDFLAGS) -c -o $@ $<

vendor/libfuzzer-ng/libFuzzer.a:
	cd vendor/libfuzzer-ng/; ./build.sh

rebuild_emulator:
ifeq ($(BACKEND), bochs)
	rm -rf vendor/lib vendor/include
	mkdir -p vendor/bochs-build vendor/lib vendor/include
	cd vendor/bochs-build; test -f config.h || ../bochs/configure \
		--enable-vmx=2 --with-vncsrv --enable-x86-64 --enable-e1000 \
		--without-x --without-x11 --without-win32 --without-macos \
		--enable-cpu-level=6 --enable-pci --without-gui --enable-pnic \
		--enable-fast-function-calls --enable-fpu --enable-cdrom \
		--enable-avx --enable-evex --disable-docbook --enable-instrumentation --with-nogui \
		--enable-gdb-stub
	cd vendor/bochs-build; make -j $(NPROCS)
	cp ./vendor/bochs-build/cpu/cpudb/libcpudb.a vendor/lib/
	cp ./vendor/bochs-build/cpu/libcpu.a vendor/lib/
	cp ./vendor/bochs-build/cpu/fpu/libfpu.a vendor/lib/
	cp ./vendor/bochs-build/cpu/avx/libavx.a vendor/lib/
	cp ./vendor/bochs-build/config.h vendor/include/
	cp ./vendor/bochs-build/pc_system.o vendor/lib/pc_system.o
	cp ./vendor/bochs/instrument/stubs/instrument.h vendor/include/
	cd vendor/bochs-build; make -j bx_debug/libdebug.a
	cp ./vendor/bochs-build/bx_debug/libdebug.a vendor/lib/
else
    $(error Unsupported backend: $(BACKEND))
endif

tests: rebuild_emulator $(OBJS) $(VENDOR_LIBS) vendor/libfuzzer-ng/libFuzzer.a
ifeq ($(ARCH), x86_64)
	$(CXX) $(CFLAGS) -I. tests/cve-2021-3947.cc $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) -o tests/cve-2021-3947
	$(CXX) $(CFLAGS) -I. tests/cve-2022-0216.cc $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) -o tests/cve-2022-0216
else
    $(error Unsupported architecture: $(ARCH))
endif

clean:
	rm -rf ./*.o backend/bochs/*.o

distclean: clean
	rm -rf vendor/lib vendor/include
	rm -rf vendor/bochs-build
