NPROCS     := 1
OS         := $(shell uname -s)
ARCH       ?= x86_64

ifeq ($(OS),Linux)
	NPROCS := $(shell grep -c ^processor /proc/cpuinfo)
endif

CC         ?= clang
CXX        ?= clang++

LDFLAGS     = -fPIE -lrt -ldl -lpthread -lsqlite3 -lstdc++fs -lcrypto #-fsanitize=address
ifeq ($(ARCH), x86_64)
INCLUDES    = -I. \
			  -I vendor/bochs \
			  -I vendor/bochs/gui \
			  -I vendor/include \
			  -I vendor/robin-map/include
ARCH_FLAGS  = -DHP_X86_64
else ifeq ($(ARCH), aarch64)
INCLUDES    = -I. \
			  -I vendor/robin-map/include # TODO
ARCH_FLAGS  = -DHP_AARCH64
else
    $(error Unsupported architecture: $(ARCH))
endif
CFLAGS      = $(INCLUDES) $(ARCH_FLAGS) -O3 -g -lsqlite3 -fPIE #-stdlib=libc++ -fsanitize=address
CXXFLAGS    =-stdlib=libc++

LIBFUZZER_FLAGS \
            = -max_len=8192 -rss_limit_mb=-1 -detect_leaks=0 -use_value_profile=1 ${LIBFUZZER_ARGS}

OBJS_GENERIC= \
			  fuzz.o \
			  cov.o \
			  db.o \
			  enum.o \
			  feedback.o \
			  conveyor.o \
			  link_map.o \
			  sourcecov.o \
			  sym2addr_linux.o \
			  symbolize.o \
			  main.o


ifeq ($(ARCH), x86_64)
VENDOR_LIBS = vendor/lib/libdebug.a vendor/lib/libcpu.a vendor/lib/libcpudb.a \
			  vendor/lib/libavx.a vendor/lib/libfpu.a \
			  vendor/libfuzzer-ng/libFuzzer.a vendor/lib/gdbstub.o 
VENDOR_OBJS =
OBJS        = $(OBJS_GENERIC) \
			  arch/x86_64/breakpoints.o \
			  arch/x86_64/devices.o \
			  arch/x86_64/ept.o \
			  arch/x86_64/control.o \
			  arch/x86_64/feedback.o \
			  arch/x86_64/instrument.o \
			  arch/x86_64/mem.o \
			  arch/x86_64/regs.o \
			  arch/x86_64/vmcs.o \
              arch/x86_64/bochsapi/logfunctions.o \
			  arch/x86_64/bochsapi/system.o \
			  arch/x86_64/bochsapi/mem.o \
              arch/x86_64/bochsapi/siminterface.o \
			  arch/x86_64/bochsapi/paramtree.o \
			  arch/x86_64/bochsapi/gui.o \
			  arch/x86_64/bochsapi/apic.o \
              arch/x86_64/bochsapi/dbg.o
else ifeq ($(ARCH), aarch64)
VENDOR_LIBS = vendor/libfuzzer-ng/libFuzzer.a # TODO
VENDOR_OBJS =
OBJS        = $(OBJS_GENERIC) \
			  arch/aarch64/breakpoints.o \
			  arch/aarch64/control.o \
			  arch/aarch64/mem.o \
			  arch/aarch64/feedback.o \
			  arch/aarch64/instrument.o \
			  arch/aarch64/regs.o # TODO
else
    $(error Unsupported architecture: $(ARCH))
endif

all: rebuild_emulator $(OBJS) $(VENDOR_LIBS) vendor/libfuzzer-ng/libFuzzer.a
	$(CXX) $(CFLAGS) $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) -o fuzz

%.o: %.cc $(DEPS)
	$(CXX) $(CFLAGS) $(LDFLAGS) -c -o $@ $< 

vendor/libfuzzer-ng/libFuzzer.a:
	cd vendor/libfuzzer-ng/; ./build.sh

rebuild_emulator:
ifeq ($(ARCH), x86_64)
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
	cp ./vendor/bochs-build/gdbstub.o vendor/lib/gdbstub.o
	cp ./vendor/bochs/instrument/stubs/instrument.h vendor/include/
	cd vendor/bochs-build; make -j bx_debug/libdebug.a
	cp ./vendor/bochs-build/bx_debug/libdebug.a vendor/lib/
else ifeq ($(ARCH), aarch64)
# TODO
else
    $(error Unsupported architecture: $(ARCH))
endif

clean:
ifeq ($(ARCH), x86_64)
	rm -rf vendor/bochs-build arch/x86_64/bochsapi/*.o
else ifeq ($(ARCH), aarch64)
# TODO
else
    $(error Unsupported architecture: $(ARCH))
endif
	rm -rf vendor/lib vendor/include
	rm -rf ./*.o
