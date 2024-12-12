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
			  -I vendor/robin-map/include \
			  -I arch/aarch64/qemuapi \
			  -I vendor/qemu/include \
			  -I vendor/qemu/target/arm \
			  -I vendor/qemu-build \
			  -I /usr/include/glib-2.0 \
			  -I /usr/lib/x86_64-linux-gnu/glib-2.0/include
ARCH_FLAGS  = -DHP_AARCH64 -DNEED_CPU_H \
			  -DCONFIG_TARGET=\"aarch64-softmmu-config-target.h\" \
			  -DCONFIG_DEVICES=\"aarch64-softmmu-config-devices.h\"
else
    $(error Unsupported architecture: $(ARCH))
endif
CFLAGS      = $(INCLUDES) $(ARCH_FLAGS) -O3 -g -lsqlite3 -fPIE #-stdlib=libc++ -fsanitize=address
CXXFLAGS    =-stdlib=libc++

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
# python3 ./scripts/gen_makefile_qemu.py vendor/qemu-build/build.ninja
include Makefile.qemu
VENDOR_LIBS:= vendor/libfuzzer-ng/libFuzzer.a
VENDOR_OBJS =
LDFLAGS    := $(LDFLAGS) -Wl,--whole-archive vendor/lib/qemu_system_aarch64.a \
			  -Wl,--no-whole-archive $(QEMU_LDFLAGS)
OBJS        = arch/aarch64/qemuapi/qemu.o \
			  arch/aarch64/breakpoints.o \
			  arch/aarch64/control.o \
			  arch/aarch64/mem.o \
			  arch/aarch64/feedback.o \
			  arch/aarch64/instrument.o \
			  arch/aarch64/regs.o \
			  $(OBJS_GENERIC)
else
    $(error Unsupported architecture: $(ARCH))
endif

all: rebuild_emulator $(OBJS) $(VENDOR_LIBS) vendor/libfuzzer-ng/libFuzzer.a
	$(CXX) $(CFLAGS) $(OBJS) $(VENDOR_OBJS) $(VENDOR_LIBS) $(LDFLAGS) -o fuzz

%.o: %.cc $(DEPS)
	$(CXX) $(CFLAGS) $(LDFLAGS) -c -o $@ $<

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

vendor/libfuzzer-ng/libFuzzer.a:
	cd vendor/libfuzzer-ng/; ./build.sh

rebuild_emulator:
ifeq ($(ARCH), x86_64)
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
	cp ./vendor/bochs/instrument/stubs/instrument.h vendor/include/
	cd vendor/bochs-build; make -j bx_debug/libdebug.a
	cp ./vendor/bochs-build/bx_debug/libdebug.a vendor/lib/
else ifeq ($(ARCH), aarch64)
	if [ ! -d "vendor/qemu" ]; then \
		git clone https://github.com/qemu/qemu.git vendor/qemu \
			--branch v8.2.7 --depth=1; \
	fi
	rm -rf vendor/lib vendor/include
	mkdir -p vendor/qemu-build
	cd vendor/qemu-build; test -f config.status || ../qemu/configure \
		--disable-vnc --disable-sdl --disable-bpf --enable-slirp \
		--disable-capstone --target-list=aarch64-softmmu
	cd vendor/qemu-build; ninja -j $(NPROCS)

	# cd vendor/qemu; meson subprojects download dtc
	# cd vendor/qemu/subprojects/dtc/; make
	# cp -r ./vendor/qemu-build/subprojects/ vendor/lib/
	# cp -r ./vendor/qemu/subprojects/dtc vendor/lib/subprojects

	rsync -av ./vendor/qemu-build/libcommon.fa.p vendor/lib/
	rsync -av ./vendor/qemu-build/libqemu-aarch64-softmmu.fa.p vendor/lib/
	mkdir -p ./vendor/lib/qemu-system-aarch64.p
	rsync -av ./vendor/qemu-build/qemu-system-aarch64.p/meson-generated_.._ui_dbus-display1.c.o \
		vendor/lib/qemu-system-aarch64.p/meson-generated_.._ui_dbus-display1.c.o

	# python3 ./scripts/gen_makefile_qemu.py vendor/qemu-build/build.ninja
	rsync -av ./vendor/qemu-build/libhwcore.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/libhwcore.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/libqom.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/libqom.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/libevent-loop-base.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/libevent-loop-base.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/gdbstub/libgdb_system.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/gdbstub/libgdb_system.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/libio.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/libio.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/libcrypto.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/libcrypto.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/libauthz.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/libauthz.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/libblockdev.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/libblockdev.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/libblock.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/libblock.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/libchardev.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/libchardev.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/libqmp.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/libqmp.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/libqemuutil.a ./vendor/lib/libqemuutil.fa
	rsync -av ./vendor/qemu-build/libqemuutil.a.p/ ./vendor/lib/libqemuutil.fa.p/
	rsync -av ./vendor/qemu-build/subprojects/libvhost-user/libvhost-user-glib.a ./vendor/lib/libvhost-user-glib.fa
	rsync -av ./vendor/qemu-build/subprojects/libvhost-user/libvhost-user-glib.a.p/ ./vendor/lib/libvhost-user-glib.fa.p/
	rsync -av ./vendor/qemu-build/subprojects/libvhost-user/libvhost-user.a ./vendor/lib/libvhost-user.fa
	rsync -av ./vendor/qemu-build/subprojects/libvhost-user/libvhost-user.a.p/ ./vendor/lib/libvhost-user.fa.p/
	rsync -av ./vendor/qemu-build/tcg/libtcg_system.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/tcg/libtcg_system.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/libmigration.fa ./vendor/lib/
	rsync -av ./vendor/qemu-build/libmigration.fa.p ./vendor/lib/
	rsync -av ./vendor/qemu-build/subprojects/libvduse/libvduse.a ./vendor/lib/libvduse.fa
	rsync -av ./vendor/qemu-build/subprojects/libvduse/libvduse.a.p/ ./vendor/lib/libvduse.fa.p/

	make $(OTHERS)
	ar cr vendor/lib/qemu_system_aarch64.a $(LIBCOMMON) $(LIBQEMU_AARCH64_SOFTMMU) $(QEMU_SYSTEM_AARCH64)
else
    $(error Unsupported architecture: $(ARCH))
endif

clean:
ifeq ($(ARCH), x86_64)
	rm -rf vendor/bochs-build arch/x86_64/bochsapi/*.o
else ifeq ($(ARCH), aarch64)
	rm -rf vendor/qemu-build #TODO
else
    $(error Unsupported architecture: $(ARCH))
endif
	rm -rf vendor/lib vendor/include
	rm -rf ./*.o
