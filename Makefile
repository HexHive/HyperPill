NPROCS     := 1
OS         := $(shell uname -s)

ifeq ($(OS),Linux)
	NPROCS := $(shell grep -c ^processor /proc/cpuinfo)
endif

CXX ?= clang++
VENDOR_LIBS = vendor/lib/libdebug.a vendor/lib/libcpu.a vendor/lib/libcpudb.a vendor/lib/libavx.a vendor/lib/libfpu.a vendor/libfuzzer-ng/libFuzzer.a vendor/lib/pc_system.o
VENDOR_OBJS =


LDFLAGS     = -fPIE -lrt -ldl -lpthread -lsqlite3 -lstdc++fs -lcrypto #-fsanitize=address
INCLUDES    = -I vendor/bochs \
			  -I vendor/bochs/gui \
			  -I vendor/include \
			  -I vendor/robin-map/include
CFLAGS      = $(INCLUDES) -O3 -g -lsqlite3 -fPIE #-stdlib=libc++ -fsanitize=address
CXXFLAGS=-stdlib=libc++

LIBFUZZER_FLAGS = -max_len=8192 -rss_limit_mb=-1 -detect_leaks=0 -use_value_profile=1 ${LIBFUZZER_ARGS}

OBJS        = main.o \
			  regs.o \
			  breakpoints.o \
			  db.o \
			  manual_ranges.o \
			  instrument.o \
			  feedback.o \
			  fuzz.o \
			  conveyor.o \
			  symbolize.o \
			  sym2addr_linux.o \
			  link_map.o \
			  ept.o \
			  cov.o \
			  vmcs.o \
			  enum.o \
			  sourcecov.o \
			  gdbstub.o \
              bochsapi/logfunctions.o \
			  devices.o \
			  bochsapi/system.o \
			  bochsapi/mem.o \
              bochsapi/siminterface.o \
			  bochsapi/paramtree.o \
			  bochsapi/gui.o \
			  bochsapi/apic.o \
              bochsapi/dbg.o
all: rebuild_bochs $(OBJS) $(VENDOR_LIBS) vendor/libfuzzer-ng/libFuzzer.a
	$(CXX) $(CFLAGS) $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) -o fuzz

%.o: %.cc $(DEPS)
	$(CXX) $(CFLAGS) $(LDFLAGS) -c -o $@ $< 

vendor/libfuzzer-ng/libFuzzer.a:
	cd vendor/libfuzzer-ng/; ./build.sh

rebuild_bochs:
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

tests: rebuild_bochs $(OBJS) $(VENDOR_LIBS) vendor/libfuzzer-ng/libFuzzer.a
	$(CXX) $(CFLAGS) -I. tests/cve-2021-3947.cc $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) -o tests/cve-2021-3947
	$(CXX) $(CFLAGS) -I. tests/cve-2022-0216.cc $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) -o tests/cve-2022-0216

clean:
	rm -rf vendor/bochs-build vendor/lib vendor/include
	rm -rf bochsapi/*.o
	rm -rf ./*.o

