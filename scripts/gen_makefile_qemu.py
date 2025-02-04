#!/usr/bin/python3
import os
import sys

def gen_makefile_qemu(path_to_build_ninja):
    objs = None
    link_args = None
    with open(path_to_build_ninja) as f:
        for line in f:
            if line.startswith('build qemu-system-aarch64:'):
                objs = line.strip().split('|')[0].split()[3:]
                continue
            if objs is not None and line.startswith(' LINK_ARGS'):
                link_args = line.strip().split()[2:]
                break

    libcommon = []
    libqemu_aarch64_softmm = []
    qemu_system_aarch64 = []
    others = []

    for obj in objs:
        if obj.startswith('libcommon.fa.p'):
            libcommon.append(obj)
        elif obj.startswith('libqemu-aarch64-softmmu.fa.p'):
            libqemu_aarch64_softmm.append(obj)
        elif obj.startswith('qemu-system-aarch64.p'):
            if obj != 'qemu-system-aarch64.p/system_main.c.o':
                qemu_system_aarch64.append(obj)
        else:
            raise ValueError(f'hey, what is {obj}?')

    real_link_args = []
    makefile_qemu_rsync = ['# this file is auto generated', '']
    for item in link_args:
        if item.endswith('.fa'):
            item_fixup = os.path.basename(item.replace('.fa', '.a'))
            if item_fixup not in others:
                others.append(item_fixup)
                makefile_qemu_rsync.append(f'rsync -av ./vendor/qemu-build/{item} ./vendor/lib/')
                makefile_qemu_rsync.append(f'rsync -av ./vendor/qemu-build/{item}.p ./vendor/lib/')
            real_link_args.append(f'vendor/lib/{item_fixup}')
        elif item.endswith('.a'):
            item_fixup = os.path.basename(item)
            if item not in others:
                others.append(item_fixup)
                makefile_qemu_rsync.append('rsync -av ./vendor/qemu-build/{} ./vendor/lib/{}'.format(item, item_fixup.replace('.a', '.fa')))
                makefile_qemu_rsync.append('rsync -av ./vendor/qemu-build/{}.p/ ./vendor/lib/{}.p/'.format(item, item_fixup.replace('.a', '.fa')))
            real_link_args.append(f'vendor/lib/{item_fixup}')
        elif item.startswith('@'):
            pass
        else:
            real_link_args.append(item)
    with open('Makefile.qemu.rsync', 'w') as f:
        for line in makefile_qemu_rsync:
            f.write(line + '\n')
    print('write to Makefile.qemu.rsync')

    makefile_qemu_env = []
    makefile_qemu_env.append('# this file is auto generated')
    makefile_qemu_env.append('')
    makefile_qemu_env.append('LIBCOMMON=" \\')
    makefile_qemu_env.extend([f'\tvendor/lib/{obj} \\' for obj in libcommon[:-1]])
    makefile_qemu_env.append(f'\tvendor/lib/{libcommon[-1]}"')
    makefile_qemu_env.append('')
    makefile_qemu_env.append('LIBQEMU_AARCH64_SOFTMMU=" \\')
    makefile_qemu_env.extend([f'\tvendor/lib/{obj} \\' for obj in libqemu_aarch64_softmm[:-1]])
    makefile_qemu_env.append(f'\tvendor/lib/{libqemu_aarch64_softmm[-1]}"')
    makefile_qemu_env.append('')
    makefile_qemu_env.append('QEMU_SYSTEM_AARCH64=" \\')
    makefile_qemu_env.extend([f'\tvendor/lib/{obj} \\' for obj in qemu_system_aarch64[:-1]])
    makefile_qemu_env.append(f'\tvendor/lib/{qemu_system_aarch64[-1]}"')
    makefile_qemu_env.append('')
    makefile_qemu_env.append('OTHERS=" \\')
    makefile_qemu_env.extend([f'\tvendor/lib/{obj} \\' for obj in others[:-1]])
    makefile_qemu_env.append(f'\tvendor/lib/{others[-1]}"')
    makefile_qemu_env.append('')
    makefile_qemu_env.append('QEMU_LDFLAGS=" \\')
    makefile_qemu_env.extend([f'\t{item} \\' for item in real_link_args[:-1]])
    makefile_qemu_env.append(f'\t{real_link_args[-1]}"')

    with open('Makefile.qemu.env', 'w') as f:
        for line in makefile_qemu_env:
            f.write(line + '\n')
    print('write to Makefile.qemu.env')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: python3 {sys.argv[0]} path/to/build/ninja')
        exit(-1)
    gen_makefile_qemu(sys.argv[1])
