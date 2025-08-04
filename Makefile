NPROCS     := 1
OS         := $(shell uname -s)
ARCH       ?= x86_64
BACKEND    ?= qemu
ifeq ($(ARCH), x86_64)
BACKEND     = bochs
BACKEND_FLAG= -DHP_BACKEND_BOCHS
else ifeq ($(ARCH), aarch64)
BACKEND     = qemu
BACKEND_FLAG= -DHP_BACKEND_QEMU
endif
ifeq ($(BACKEND), bochs)
ARCH        = x86_64
endif
ifeq ($(BACKEND), qemu)
ARCH        = aarch64
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
else ifeq ($(BACKEND), qemu)
INCLUDES    = -I. \
			  -I vendor/robin-map/include \
			  -I backends/qemu \
			  -I vendor/qemu/include \
			  -I vendor/qemu/plugins \
			  -I vendor/qemu/ \
			  -I vendor/qemu-build \
			  -I /usr/include/glib-2.0 \
			  -I /usr/lib/x86_64-linux-gnu/glib-2.0/include
ifeq ($(ARCH), aarch64)
ARCH_FLAGS  = -I vendor/qemu/target/arm \
			  -DHP_AARCH64 -DNEED_CPU_H \
			  -DCONFIG_TARGET=\"aarch64-softmmu-config-target.h\" \
			  -DCONFIG_DEVICES=\"aarch64-softmmu-config-devices.h\"
endif
else
    $(error Unsupported architecture: $(ARCH))
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
			  symbolize.o

ifeq ($(BACKEND), bochs)
VENDOR_LIBS = vendor/lib/libdebug.a vendor/lib/libcpu.a vendor/lib/libcpudb.a \
			  vendor/lib/libavx.a vendor/lib/libfpu.a \
			  vendor/libfuzzer-ng/libFuzzer.a vendor/lib/gdbstub.o vendor/lib/pc_system.o
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
else ifeq ($(BACKEND), qemu)

MAKEFLAGS += --no-builtin-rules
%.a: %.fa %.fa.p
	ar cr $@ $*.fa.p/*.o

VENDOR_LIBS:= vendor/libfuzzer-ng/libFuzzer.a
VENDOR_OBJS =
LDFLAGS    := $(LDFLAGS) -Wl,--whole-archive vendor/lib/qemu_system_aarch64.a \
			  -Wl,--no-whole-archive
OBJS        = backends/qemu/breakpoints.o \
			  backends/qemu/control.o \
			  backends/qemu/init.o \
			  backends/qemu/instrument.o \
			  backends/qemu/mem.o \
			  backends/qemu/regs.o \
			  backends/qemu/s2pt.o \
			  backends/qemu/at.o \
			  backends/qemu/nested.o \
			  backends/qemu/dbg.o \
			  $(OBJS_GENERIC)
else
    $(error Unsupported architecture: $(ARCH))
endif

all: rebuild_emulator $(OBJS) $(VENDOR_LIBS) vendor/libfuzzer-ng/libFuzzer.a
ifeq ($(ARCH), x86_64)
	$(CXX) $(CFLAGS) $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) -o fuzz
else ifeq ($(ARCH), aarch64)
	. ./Makefile.qemu.env && export QEMU_LDFLAGS && \
	$(CXX) $(CFLAGS) $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) $$QEMU_LDFLAGS -o fuzz
endif

%.o: %.cc $(DEPS)
	$(CXX) $(CFLAGS) $(LDFLAGS) -c -o $@ $<

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

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
	cp ./vendor/bochs-build/gdbstub.o vendor/lib/gdbstub.o
	cp ./vendor/bochs-build/pc_system.o vendor/lib/pc_system.o
	cp ./vendor/bochs/instrument/stubs/instrument.h vendor/include/
	cd vendor/bochs-build; make -j bx_debug/libdebug.a
	cp ./vendor/bochs-build/bx_debug/libdebug.a vendor/lib/
else ifeq ($(BACKEND), qemu)
	if [ ! -d "vendor/qemu" ]; then \
		git clone https://github.com/qemu/qemu.git vendor/qemu \
			--branch v8.2.7 --depth=1; \
		cd vendor/qemu; \
		git am ../../Makefile.qemu.patch; \
		cd ../..; \
	fi
	rm -rf vendor/lib vendor/include
	mkdir -p vendor/qemu-build
	cd vendor/qemu-build; test -f config.status || ../qemu/configure \
		--disable-vnc --disable-sdl --disable-bpf --enable-slirp \
		--enable-capstone --target-list=aarch64-softmmu
	cd vendor/qemu-build; ninja -j $(NPROCS)

	# cd vendor/qemu; meson subprojects download dtc
	# cd vendor/qemu/subprojects/dtc/; make
	# cp -r ./vendor/qemu-build/subprojects/ vendor/lib/
	# cp -r ./vendor/qemu/subprojects/dtc vendor/lib/subprojects

	rsync -av ./vendor/qemu-build/libcommon.fa.p vendor/lib/
ifeq ($(ARCH), aarch64)
	rsync -av ./vendor/qemu-build/libqemu-aarch64-softmmu.fa.p vendor/lib/
	mkdir -p ./vendor/lib/qemu-system-aarch64.p
	rsync -av ./vendor/qemu-build/qemu-system-aarch64.p/meson-generated_.._ui_dbus-display1.c.o \
		vendor/lib/qemu-system-aarch64.p/meson-generated_.._ui_dbus-display1.c.o
endif

	python3 ./scripts/gen_makefile_qemu.py vendor/qemu-build/build.ninja
ifeq ($(ARCH), aarch64)
	chmod +x Makefile.qemu.rsync && bash -x Makefile.qemu.rsync
	. ./Makefile.qemu.env && export LIBCOMMON LIBQEMU_AARCH64_SOFTMMU QEMU_SYSTEM_AARCH64 OTHERS && \
		make $$OTHERS && \
		ar cr vendor/lib/qemu_system_aarch64.a $$LIBCOMMON $$LIBQEMU_AARCH64_SOFTMMU $$QEMU_SYSTEM_AARCH64
endif
else
    $(error Unsupported architecture: $(ARCH))
endif


clean:
	rm -rf ./*.o backends/bochs/*.o backends/qemu/*.o

distclean: clean
	rm -rf vendor/lib vendor/include
	rm -rf vendor/bochs-build vendor/qemu-build
