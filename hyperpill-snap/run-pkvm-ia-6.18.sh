#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE_URL="${IMAGE_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2}"
ROOTFS_URL="${ROOTFS_URL:-https://github.com/HexHive/HyperPill/raw/refs/heads/main/hyperpill-snap/x86_64/rootfs.cpio.gz}"
BASE_IMAGE="${BASE_IMAGE:-$SCRIPT_DIR/debian-12-genericcloud-amd64.qcow2}"
OVERLAY_IMAGE="${OVERLAY_IMAGE:-$SCRIPT_DIR/debian-12-pkvm-ia-6.18.qcow2}"
OVERLAY_SIZE="${OVERLAY_SIZE:-40G}"
SEED_IMAGE="${SEED_IMAGE:-$SCRIPT_DIR/debian-12-pkvm-ia-6.18-seed.img}"
USER_DATA="${USER_DATA:-$SCRIPT_DIR/debian-12-pkvm-ia-6.18-user-data}"
META_DATA="${META_DATA:-$SCRIPT_DIR/debian-12-pkvm-ia-6.18-meta-data}"
PID_FILE="${PID_FILE:-$SCRIPT_DIR/debian-12-pkvm-ia-6.18.pid}"
SERIAL_LOG="${SERIAL_LOG:-$SCRIPT_DIR/debian-12-pkvm-ia-6.18-serial.log}"
SSH_PORT="${SSH_PORT:-2222}"
VM_NAME="${VM_NAME:-pkvm-ia-6.18}"
VM_USER="${VM_USER:-pkvm}"
VM_PASSWORD="${VM_PASSWORD:-root}"
VM_MEM_MB="${VM_MEM_MB:-12288}"
VM_CPUS="${VM_CPUS:-12}"
REPO_URL="${REPO_URL:-https://github.com/intel-staging/pKVM-IA.git}"
REPO_DIRNAME="${REPO_DIRNAME:-pKVM-IA}"
REPO_BRANCH="${REPO_BRANCH:-pkvm-v6.18}"
CROSVM_REPO_URL="${CROSVM_REPO_URL:-https://github.com/google/crosvm.git}"
GUEST_SHARED_MOUNT="${GUEST_SHARED_MOUNT:-/home/${VM_USER}/pkvm-ia-6.18}"
ROOTFS_NAME="${ROOTFS_NAME:-rootfs.cpio.gz}"
TMUX_SESSION="${TMUX_SESSION:-pkvm-ia-6.18}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
QEMU_IMG_BIN="${QEMU_IMG_BIN:-qemu-img}"

REPO_PATH="${GUEST_SHARED_MOUNT}/${REPO_DIRNAME}"
CROSVM_DIR="${GUEST_SHARED_MOUNT}/crosvm"
HOST_BUILD_DIR="${GUEST_SHARED_MOUNT}/out/pkvm-host"
GUEST_BUILD_DIR="${GUEST_SHARED_MOUNT}/out/pkvm-guest"
ROOTFS_PATH="${GUEST_SHARED_MOUNT}/${ROOTFS_NAME}"
HOST_KERNEL_PATH="${HOST_BUILD_DIR}/arch/x86/boot/bzImage"
GUEST_KERNEL_PATH="${GUEST_BUILD_DIR}/arch/x86/boot/bzImage"
CROSVM_BIN_PATH="${CROSVM_DIR}/target/release/crosvm"
LAUNCH_LOG="${GUEST_SHARED_MOUNT}/launch-pvm.log"
HOST_KERNEL_CMD_ARG="${HOST_KERNEL_CMD_ARG:-kvm-intel.pkvm=1}"
HOST_HELPER_PATH="${SCRIPT_DIR}/${VM_NAME}-helper.sh"
HOST_LOG_PREFIX="${SCRIPT_DIR}/${VM_NAME}"

usage() {
  cat <<EOF
Usage:
  $(basename "$0") start
  $(basename "$0") stop
  $(basename "$0") clean

Start flow:
  1. Download the Debian cloud image if missing
  2. Boot the Debian guest
  3. Create a guest-local work directory at ${GUEST_SHARED_MOUNT}
  4. Clone ${REPO_URL} into the guest-local work directory and check out ${REPO_BRANCH}
  5. Run:
       embedded helper: build-host
       embedded helper: build-guest
       download ${ROOTFS_URL}
       install the guest host kernel and append ${HOST_KERNEL_CMD_ARG}
       reboot the guest into the new host kernel
       verify dmesg contains KVM lines
       build crosvm from ${CROSVM_REPO_URL}
  6. Open a tmux session with:
       - host window: interactive shell in the Debian guest
       - pkvm window: launch-pvm console

Commands:
  start       Run the full boot, build, download, and tmux workflow.
  stop        Stop the Debian guest.
  clean       Stop the guest and remove generated VM/build artifacts.

Notes:
  - Help does not install host dependencies.
  - start installs host-side sshpass if needed.
  - There is no separate host-side pkvm-ia-helper.sh anymore.
  - The embedded helper is copied into ${GUEST_SHARED_MOUNT}/pkvm-ia-helper.sh during start.
  - Build outputs live under ${GUEST_SHARED_MOUNT}/out
  - crosvm is built inside the guest with cargo/rustup
  - launch-pvm still requires a pKVM-capable host kernel
EOF
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

install_host_dependency() {
  local pkg="$1"

  if have_cmd "$pkg"; then
    log "Host dependency already present: $pkg"
    return
  fi
  if ! have_cmd apt-get; then
    echo "Missing required command: $pkg (and apt-get is unavailable for auto-install)" >&2
    exit 1
  fi

  log "Installing host dependency: $pkg"
  if [[ "${EUID}" -eq 0 ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
    return
  fi
  if have_cmd sudo; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
    return
  fi

  echo "Missing required command: $pkg (rerun as root or install sudo)" >&2
  exit 1
}

ensure_host_dependency() {
  local cmd="$1"
  local pkg="$2"

  if have_cmd "$cmd"; then
    log "Host dependency already present: $cmd"
    return
  fi

  log "Host dependency missing: $cmd; installing package $pkg"
  install_host_dependency "$pkg"

  if ! have_cmd "$cmd"; then
    echo "Missing required command after installing ${pkg}: ${cmd}" >&2
    exit 1
  fi
}

ensure_host_dependencies() {
  ensure_host_dependency "$QEMU_BIN" qemu-system-x86
  ensure_host_dependency "$QEMU_IMG_BIN" qemu-utils
  ensure_host_dependency cloud-localds cloud-image-utils
  ensure_host_dependency ssh openssh-client
  ensure_host_dependency scp openssh-client
  ensure_host_dependency curl curl
  ensure_host_dependency tmux tmux
  ensure_host_dependency sshpass sshpass
}

require_cmds() {
  local missing=0
  local cmd
  for cmd in "$@"; do
    if ! have_cmd "$cmd"; then
      echo "Missing required command: $cmd" >&2
      missing=1
    fi
  done
  ((missing == 0))
}

write_cloud_init() {
  cat >"$USER_DATA" <<EOF
#cloud-config
hostname: ${VM_NAME}
manage_etc_hosts: true
users:
  - name: ${VM_USER}
    shell: /bin/bash
    groups: sudo
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    plain_text_passwd: ${VM_PASSWORD}
disable_root: true
ssh_pwauth: true
chpasswd:
  list: |
    ${VM_USER}:${VM_PASSWORD}
  expire: false
package_update: false
packages:
  - git
  - curl
  - ca-certificates
  - build-essential
  - bc
  - bison
  - flex
  - libelf-dev
  - libssl-dev
  - dwarves
  - cpio
  - rsync
  - python3
  - tmux
  - psmisc
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
runcmd:
  - [ sh, -lc, 'grep -q "^127.0.0.1[[:space:]]\\+archive.ubuntu.com" /etc/hosts && sed -i "/archive.ubuntu.com/d" /etc/hosts || true' ]
EOF

  cat >"$META_DATA" <<EOF
instance-id: ${VM_NAME}
local-hostname: ${VM_NAME}
EOF

  cloud-localds "$SEED_IMAGE" "$USER_DATA" "$META_DATA"
}

download_image() {
  if [[ -f "$BASE_IMAGE" ]]; then
    return
  fi

  echo "Downloading Debian image to $BASE_IMAGE"
  curl -fL "$IMAGE_URL" -o "$BASE_IMAGE"
}

create_overlay_if_needed() {
  if [[ -f "$OVERLAY_IMAGE" ]]; then
    return
  fi

  "$QEMU_IMG_BIN" create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY_IMAGE" "$OVERLAY_SIZE" >/dev/null
}

write_embedded_helper() {
  cat >"$HOST_HELPER_PATH" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$PWD/pKVM-IA}"
ARCH="${ARCH:-x86_64}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 8)}"
HOST_BUILD_DIR="${HOST_BUILD_DIR:-$ROOT_DIR/../out/pkvm-host}"
GUEST_BUILD_DIR="${GUEST_BUILD_DIR:-$ROOT_DIR/../out/pkvm-guest}"
CROSVM_BIN="${CROSVM_BIN:-crosvm}"
DEFAULT_BLOCK_PARAMS="root=/dev/vda rw console=ttyS0"
DEFAULT_INITRAMFS_PARAMS="console=ttyS0 rdinit=/init"

require_root_tree() {
  if [[ ! -d "$ROOT_DIR" ]]; then
    echo "error: ROOT_DIR does not exist: $ROOT_DIR" >&2
    exit 1
  fi
  if [[ ! -x "$ROOT_DIR/scripts/config" ]]; then
    echo "error: missing kernel helper: $ROOT_DIR/scripts/config" >&2
    exit 1
  fi
}

ensure_build_dir() {
  mkdir -p "$1"
}

run_make() {
  make -C "$ROOT_DIR" O="$1" ARCH="$ARCH" -j"$JOBS" "${@:2}"
}

host_kernel_release() {
  make -s -C "$ROOT_DIR" O="$HOST_BUILD_DIR" ARCH="$ARCH" kernelrelease
}

set_host_config() {
  ensure_build_dir "$HOST_BUILD_DIR"
  run_make "$HOST_BUILD_DIR" x86_64_defconfig
  "$ROOT_DIR/scripts/config" --file "$HOST_BUILD_DIR/.config" \
    --enable KVM \
    --enable KVM_INTEL \
    --enable INTEL_IOMMU \
    --disable KSM \
    --enable PKVM_INTEL \
    --disable PKVM_X86_GUEST \
    --disable UNWINDER_ORC \
    --enable UNWINDER_FRAME_POINTER \
    --enable FRAME_POINTER
  run_make "$HOST_BUILD_DIR" olddefconfig
}

set_guest_config() {
  ensure_build_dir "$GUEST_BUILD_DIR"
  run_make "$GUEST_BUILD_DIR" x86_64_defconfig
  "$ROOT_DIR/scripts/config" --file "$GUEST_BUILD_DIR/.config" \
    --enable KVM_GUEST \
    --enable PKVM_X86_GUEST \
    --disable PKVM_INTEL \
    --disable UNWINDER_ORC \
    --enable UNWINDER_FRAME_POINTER \
    --enable FRAME_POINTER
  run_make "$GUEST_BUILD_DIR" olddefconfig
}

build_host() {
  require_root_tree
  echo "building host kernel into $HOST_BUILD_DIR"
  set_host_config
  run_make "$HOST_BUILD_DIR" bzImage modules
}

install_host_kernel() {
  require_root_tree
  ensure_build_dir "$HOST_BUILD_DIR"
  local kernel_release
  kernel_release="$(host_kernel_release)"

  if [[ -d "/lib/modules/${kernel_release}" && -f "/boot/vmlinuz-${kernel_release}" ]]; then
    echo "host kernel ${kernel_release} already installed; skipping"
    return
  fi

  make -C "$ROOT_DIR" O="$HOST_BUILD_DIR" ARCH="$ARCH" modules_install
  if command -v installkernel >/dev/null 2>&1; then
    make -C "$ROOT_DIR" O="$HOST_BUILD_DIR" ARCH="$ARCH" install
    return
  fi

  echo "error: installkernel not found; cannot install host kernel automatically" >&2
  exit 1
}

build_guest() {
  require_root_tree
  echo "building guest kernel into $GUEST_BUILD_DIR"
  set_guest_config
  run_make "$GUEST_BUILD_DIR" bzImage modules
}

launch_pvm() {
  local kernel=""
  local disk=""
  local initrd=""
  local cpus="4"
  local mem="4096"
  local params="$DEFAULT_BLOCK_PARAMS"
  local params_explicit=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --kernel)
        kernel="$2"
        shift 2
        ;;
      --disk)
        disk="$2"
        shift 2
        ;;
      --initrd)
        initrd="$2"
        shift 2
        ;;
      --cpus)
        cpus="$2"
        shift 2
        ;;
      --mem)
        mem="$2"
        shift 2
        ;;
      --params)
        params="$2"
        params_explicit=1
        shift 2
        ;;
      *)
        echo "error: unknown launch-pvm argument: $1" >&2
        exit 1
        ;;
    esac
  done

  [[ -n "$kernel" ]] || { echo "error: --kernel PATH is required" >&2; exit 1; }
  [[ -f "$kernel" ]] || { echo "error: kernel not found: $kernel" >&2; exit 1; }
  [[ -z "$disk" || -f "$disk" ]] || { echo "error: disk not found: $disk" >&2; exit 1; }
  [[ -z "$initrd" || -f "$initrd" ]] || { echo "error: initrd not found: $initrd" >&2; exit 1; }

  if [[ -n "$disk" && -n "$initrd" && $params_explicit -eq 0 ]]; then
    params="$DEFAULT_BLOCK_PARAMS"
  elif [[ -n "$initrd" && $params_explicit -eq 0 ]]; then
    params="$DEFAULT_INITRAMFS_PARAMS"
  fi
  command -v "$CROSVM_BIN" >/dev/null 2>&1 || { echo "error: crosvm not found: $CROSVM_BIN" >&2; exit 1; }

  local -a cmd=(
    "$CROSVM_BIN" run
    --disable-sandbox
    --cpus "$cpus"
    --mem "$mem"
    --protected-vm-without-firmware
    --serial type=stdout,hardware=serial,num=1,console,stdin
    --params "$params"
  )

  [[ -n "$initrd" ]] && cmd+=(--initrd "$initrd")
  [[ -n "$disk" ]] && cmd+=(--block "path=$disk,root")
  cmd+=("$kernel")

  exec "${cmd[@]}"
}

main() {
  case "${1:-}" in
    build-host)
      shift
      build_host "$@"
      ;;
    install-host-kernel)
      shift
      install_host_kernel "$@"
      ;;
    build-guest)
      shift
      build_guest "$@"
      ;;
    launch-pvm)
      shift
      launch_pvm "$@"
      ;;
    *)
      echo "usage: $0 {build-host|install-host-kernel|build-guest|launch-pvm ...}" >&2
      exit 1
      ;;
  esac
}

main "$@"
EOF
  chmod +x "$HOST_HELPER_PATH"
}

sync_embedded_helper() {
  log "Copying embedded helper to guest work directory"
  ssh_guest "mkdir -p '${GUEST_SHARED_MOUNT}'"
  scp_guest "$HOST_HELPER_PATH" "${VM_USER}@127.0.0.1:${GUEST_SHARED_MOUNT}/pkvm-ia-helper.sh"
}

vm_running() {
  if [[ -f "$PID_FILE" ]]; then
    local pid
    pid="$(<"$PID_FILE")"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
  fi

  ps -ef | grep -F -- "-name $VM_NAME" | grep -F -- "$OVERLAY_IMAGE" | grep -F -v grep >/dev/null 2>&1
}

ssh_opts=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=10
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -p "$SSH_PORT"
)

scp_opts=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=10
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -P "$SSH_PORT"
)

ssh_guest() {
  sshpass -p "$VM_PASSWORD" ssh "${ssh_opts[@]}" "${VM_USER}@127.0.0.1" "$@"
}

ssh_guest_timeout() {
  local duration="$1"
  shift
  timeout -k 5s "$duration" sshpass -p "$VM_PASSWORD" ssh "${ssh_opts[@]}" "${VM_USER}@127.0.0.1" "$@"
}

scp_guest() {
  sshpass -p "$VM_PASSWORD" scp "${scp_opts[@]}" "$@"
}

wait_for_ssh() {
  local tries="${1:-180}"
  local i
  log "Waiting for guest SSH on port ${SSH_PORT}"
  for ((i = 1; i <= tries; i++)); do
    if ssh_guest "true" >/dev/null 2>&1; then
      log "Guest SSH is ready on attempt ${i}/${tries}"
      return 0
    fi
    if ((i == 1 || i % 15 == 0)); then
      log "Guest SSH not ready yet (${i}/${tries})"
    fi
    sleep 2
  done

  echo "Timed out waiting for SSH on port ${SSH_PORT}" >&2
  exit 1
}

start_vm() {
  if vm_running; then
    if [[ -f "$PID_FILE" ]]; then
      log "VM is already running (pid $(<"$PID_FILE"))."
    else
      log "VM is already running."
    fi
    echo "Run '$(basename "$0") stop' to stop the existing VM first." >&2
    exit 1
  fi

  if [[ -f "$PID_FILE" ]]; then
    log "Removing stale PID file: $PID_FILE"
    rm -f "$PID_FILE"
  fi

  : >"$SERIAL_LOG"

  local accel="tcg"
  local cpu_model="max"
  if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
    accel="kvm"
    cpu_model="host,+vmx,kvm-pv-unhalt=off,kvm-pv-ipi=off,kvm-pv-sched-yield=off"
  fi

  log "Starting VM ${VM_NAME} with accel=${accel} cpu=${cpu_model} ssh_port=${SSH_PORT}"

  "$QEMU_BIN" \
    -name "$VM_NAME" \
    -machine q35,accel="$accel",kernel-irqchip=split \
    -cpu "$cpu_model" \
    -smp "$VM_CPUS" \
    -m "$VM_MEM_MB" \
    -object "memory-backend-memfd,id=mem,size=${VM_MEM_MB}M,share=on" \
    -numa "node,memdev=mem" \
    -drive if=virtio,file="$OVERLAY_IMAGE",format=qcow2 \
    -drive if=virtio,file="$SEED_IMAGE",format=raw \
    -netdev user,id=net0,hostfwd=tcp::"${SSH_PORT}"-:22 \
    -device virtio-net-pci,netdev=net0 \
    -device virtio-rng-pci \
    -device intel-iommu,aw-bits=48 \
    -display none \
    -monitor none \
    -serial "file:${SERIAL_LOG}" \
    -pidfile "$PID_FILE" \
    -daemonize
}

run_guest_logged() {
  local label="$1"
  local command="$2"
  local safe_label="${label//[^a-zA-Z0-9_.-]/_}"
  local log_path="${GUEST_SHARED_MOUNT}/logs/${safe_label}.log"
  local host_log_path="${HOST_LOG_PREFIX}-${safe_label}.log"
  local remote_cmd

  echo "guest[$label] $command"
  printf -v remote_cmd '%q' "set -euo pipefail; ${command}"
  ssh_guest "bash -lc ${remote_cmd}" | tee "$host_log_path"
  echo "guest[$label] log saved to ${log_path}"
}

prepare_guest() {
  log "Preparing guest dependencies and shared mount"
  log "Waiting for cloud-init to finish"
  ssh_guest "cloud-init status --wait >/dev/null"
  log "Updating guest package metadata"
  ssh_guest "sudo apt-get update"
  log "Installing guest build and kernel dependencies"
  ssh_guest "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y git curl ca-certificates build-essential bc bison flex cpio rsync python3 python3-dev dwarves pahole libelf-dev libssl-dev libncurses-dev libdw-dev pkg-config zstd lz4 xz-utils kmod file tmux psmisc mount bindgen clang libasound2-dev libcap-dev libdbus-1-dev libdrm-dev libepoxy-dev libwayland-bin libwayland-dev protobuf-compiler wayland-protocols libusb-1.0-0-dev libfdt-dev initramfs-tools linux-base"

  log "Preparing guest-local work directory at ${GUEST_SHARED_MOUNT}"
  ssh_guest "mkdir -p '${GUEST_SHARED_MOUNT}/out' '${GUEST_SHARED_MOUNT}/logs'"

  log "Refreshing embedded helper script in guest work directory"
  write_embedded_helper
  sync_embedded_helper

  log "Ensuring guest kernel repo exists at ${REPO_PATH}"
  ssh_guest "if [[ ! -d '${REPO_PATH}/.git' ]]; then git clone '${REPO_URL}' '${REPO_PATH}'; fi"
  log "Checking out guest kernel branch ${REPO_BRANCH}"
  ssh_guest "bash -lc 'cd \"${REPO_PATH}\" && git fetch origin && git checkout \"${REPO_BRANCH}\" && git pull --ff-only origin \"${REPO_BRANCH}\"'"
  ssh_guest "cd '${REPO_PATH}' && git remote -v | head -n 1"
  log "Guest preparation complete"
}

append_guest_kernel_cmdline() {
  log "Ensuring guest kernel cmdline contains ${HOST_KERNEL_CMD_ARG}"
  ssh_guest "sudo bash -lc '
set -euo pipefail
arg=\"${HOST_KERNEL_CMD_ARG}\"
grub_cfg=/etc/default/grub
if [[ ! -f \"\$grub_cfg\" ]]; then
  echo \"error: missing \$grub_cfg\" >&2
  exit 1
fi

key=GRUB_CMDLINE_LINUX_DEFAULT
current=\$(sed -n \"s/^GRUB_CMDLINE_LINUX_DEFAULT=\\\"\\(.*\\)\\\"/\\1/p\" \"\$grub_cfg\" | head -n1)
if [[ -z \"\$current\" ]] && grep -q \"^GRUB_CMDLINE_LINUX=\" \"\$grub_cfg\"; then
  key=GRUB_CMDLINE_LINUX
  current=\$(sed -n \"s/^GRUB_CMDLINE_LINUX=\\\"\\(.*\\)\\\"/\\1/p\" \"\$grub_cfg\" | head -n1)
fi

if [[ \" \$current \" == *\" \$arg \"* ]]; then
  echo \"kernel cmdline already contains \$arg; skipping\"
  exit 0
fi

updated=\${current:+\$current }\$arg
if grep -q \"^\${key}=\" \"\$grub_cfg\"; then
  sed -i \"s|^\${key}=.*|\${key}=\\\"\$updated\\\"|\" \"\$grub_cfg\"
else
  printf \"%s=\\\"%s\\\"\\n\" \"\$key\" \"\$updated\" >> \"\$grub_cfg\"
fi

if command -v update-grub >/dev/null 2>&1; then
  update-grub
elif command -v update-grub2 >/dev/null 2>&1; then
  update-grub2
else
  echo \"error: update-grub not found\" >&2
  exit 1
fi
'"
}

guest_reboot_required() {
  ssh_guest "bash -lc '
set -euo pipefail
release=\$(make -s -C \"${REPO_PATH}\" O=\"${HOST_BUILD_DIR}\" ARCH=x86_64 kernelrelease)
if [[ \"\$(uname -r)\" != \"\$release\" ]]; then
  exit 0
fi
if [[ \" \$(cat /proc/cmdline) \" != *\" ${HOST_KERNEL_CMD_ARG} \"* ]]; then
  exit 0
fi
exit 1
'"
}

reboot_guest_and_wait() {
  if ! guest_reboot_required; then
    log "Guest already running the built host kernel with ${HOST_KERNEL_CMD_ARG}; skipping reboot"
    return
  fi

  log "Rebooting guest to pick up the installed host kernel"
  ssh_guest "nohup sudo bash -lc 'sleep 1; reboot' >/dev/null 2>&1 &" || true
  local i
  for ((i = 0; i < 30; i++)); do
    if ! ssh_guest "true" >/dev/null 2>&1; then
      log "Guest SSH dropped after reboot request"
      break
    fi
    sleep 1
  done
  wait_for_ssh
  log "Guest reboot complete and SSH is back"
}

verify_guest_kvm_enabled() {
  log "Verifying rebooted guest reports KVM lines in dmesg"
  run_guest_logged "verify-kvm" "sudo dmesg | grep -i kvm"
}

install_crosvm_guest() {
  log "Ensuring guest rust toolchain and crosvm are ready"
  run_guest_logged "install-rustup" "if [[ ! -x \$HOME/.cargo/bin/cargo ]]; then curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable; fi"
  run_guest_logged "clone-crosvm" "if [[ ! -d '${CROSVM_DIR}/.git' ]]; then git clone '${CROSVM_REPO_URL}' '${CROSVM_DIR}'; fi"
  run_guest_logged "sync-crosvm-submodules" "cd '${CROSVM_DIR}' && git submodule update --init"
  run_guest_logged "build-crosvm" "if [[ -x '${CROSVM_BIN_PATH}' ]]; then echo 'crosvm already built; skipping'; else source \$HOME/.cargo/env && cd '${CROSVM_DIR}' && cargo build --release; fi"
}

run_build_flow() {
  log "Starting guest build and install flow"
  run_guest_logged "build-host" "if [[ -f '${HOST_KERNEL_PATH}' ]]; then echo 'host kernel already built; skipping'; else cd '${GUEST_SHARED_MOUNT}' && ROOT_DIR='${REPO_PATH}' HOST_BUILD_DIR='${HOST_BUILD_DIR}' GUEST_BUILD_DIR='${GUEST_BUILD_DIR}' ./pkvm-ia-helper.sh build-host; fi"
  run_guest_logged "build-guest" "if [[ -f '${GUEST_KERNEL_PATH}' ]]; then echo 'guest kernel already built; skipping'; else cd '${GUEST_SHARED_MOUNT}' && ROOT_DIR='${REPO_PATH}' HOST_BUILD_DIR='${HOST_BUILD_DIR}' GUEST_BUILD_DIR='${GUEST_BUILD_DIR}' ./pkvm-ia-helper.sh build-guest; fi"
  run_guest_logged "download-rootfs" "if [[ -f '${ROOTFS_PATH}' ]]; then echo 'rootfs already present; skipping'; else cd '${GUEST_SHARED_MOUNT}' && curl -fL '${ROOTFS_URL}' -o '${ROOTFS_NAME}'; fi"
  run_guest_logged "install-host-kernel" "cd '${GUEST_SHARED_MOUNT}' && sudo env ROOT_DIR='${REPO_PATH}' HOST_BUILD_DIR='${HOST_BUILD_DIR}' GUEST_BUILD_DIR='${GUEST_BUILD_DIR}' ./pkvm-ia-helper.sh install-host-kernel"
  append_guest_kernel_cmdline
  reboot_guest_and_wait
  verify_guest_kvm_enabled
  write_embedded_helper
  sync_embedded_helper
  install_crosvm_guest
  log "Guest build and install flow complete"
}

require_guest_launch_prereqs() {
  ssh_guest "test -x '${GUEST_SHARED_MOUNT}/pkvm-ia-helper.sh'"
  ssh_guest "test -f '${GUEST_KERNEL_PATH}'"
  ssh_guest "test -f '${ROOTFS_PATH}'"
  if ! ssh_guest "test -x '${CROSVM_BIN_PATH}'"; then
    cat <<EOF >&2
Guest prerequisite missing: crosvm

launch-pvm in pkvm-ia-helper.sh uses crosvm inside the Debian guest.
Build crosvm in the guest, then rerun:
  $(basename "$0") pkvm-shell
EOF
    exit 1
  fi
}

host_shell_cmd() {
  printf "sshpass -p %q ssh %s %q@127.0.0.1\n" \
    "$VM_PASSWORD" \
    "${ssh_opts[*]}" \
    "$VM_USER"
}

guest_work_shell_cmd() {
  printf "sshpass -p %q ssh %s %q@127.0.0.1 %q\n" \
    "$VM_PASSWORD" \
    "${ssh_opts[*]}" \
    "$VM_USER" \
    "bash -lc 'cd \"${GUEST_SHARED_MOUNT}\" && exec \${SHELL:-/bin/bash} -l'"
}

pkvm_shell_cmd() {
  printf "sshpass -p %q ssh %s %q@127.0.0.1 %q\n" \
    "$VM_PASSWORD" \
    "${ssh_opts[*]}" \
    "$VM_USER" \
    "bash -lc 'cd \"${GUEST_SHARED_MOUNT}\" && sudo env ROOT_DIR=\"${REPO_PATH}\" HOST_BUILD_DIR=\"${HOST_BUILD_DIR}\" GUEST_BUILD_DIR=\"${GUEST_BUILD_DIR}\" CROSVM_BIN=\"${CROSVM_BIN_PATH}\" ./pkvm-ia-helper.sh launch-pvm --kernel \"${GUEST_KERNEL_PATH}\" --initrd \"${ROOTFS_PATH}\" | tee \"${LAUNCH_LOG}\"'"
}

guest_launch_cmd() {
  printf "cd %q && sudo env ROOT_DIR=%q HOST_BUILD_DIR=%q GUEST_BUILD_DIR=%q CROSVM_BIN=%q ./pkvm-ia-helper.sh launch-pvm --kernel %q --initrd %q | tee %q\n" \
    "$GUEST_SHARED_MOUNT" \
    "$REPO_PATH" \
    "$HOST_BUILD_DIR" \
    "$GUEST_BUILD_DIR" \
    "$CROSVM_BIN_PATH" \
    "$GUEST_KERNEL_PATH" \
    "$ROOTFS_PATH" \
    "$LAUNCH_LOG"
}

spawn_tmux_shells() {
  require_cmds tmux
  local tmux_session_name="${TMUX_SESSION//[^a-zA-Z0-9_-]/_}"
  local session_target="$tmux_session_name"
  local guest_window_target="${tmux_session_name}:guest"
  local launch_cmd

  if tmux has-session -t "$session_target" 2>/dev/null; then
    tmux kill-session -t "$session_target"
  fi

  local host_cmd
  host_cmd="$(host_shell_cmd)"
  launch_cmd="$(guest_launch_cmd)"

  tmux new-session -d -s "$tmux_session_name" -n host "$host_cmd"
  tmux new-window -t "$session_target" -n guest "$host_cmd"
  tmux send-keys -t "$guest_window_target" "$launch_cmd" C-m
  tmux select-window -t "$guest_window_target"
  if [[ -t 1 ]]; then
    exec tmux attach-session -t "$session_target"
  fi
  echo "Spawned tmux session: $tmux_session_name"
}

stop_vm() {
  if ! vm_running; then
    echo "VM is not running."
    rm -f "$PID_FILE"
    return
  fi

  local pid
  pid="$(<"$PID_FILE")"
  kill "$pid"

  local i
  for ((i = 0; i < 20; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$PID_FILE"
      echo "Stopped VM."
      return
    fi
    sleep 1
  done

  echo "VM did not exit after SIGTERM; pid=${pid}" >&2
  exit 1
}

status_vm() {
  if vm_running; then
    echo "running pid=$(<"$PID_FILE") ssh_port=${SSH_PORT} guest_work_dir=${GUEST_SHARED_MOUNT}"
    return
  fi
  echo "stopped"
}

reset_vm() {
  stop_vm || true
  rm -f "$OVERLAY_IMAGE" "$SEED_IMAGE" "$USER_DATA" "$META_DATA" "$SERIAL_LOG" "$HOST_HELPER_PATH"
  rm -f "${HOST_LOG_PREFIX}"-*.log
  echo "Removed generated VM and build state."
}

main() {
  local action="${1:-start}"
  shift || true

  case "$action" in
  start)
    ensure_host_dependencies
    require_cmds "$QEMU_BIN" "$QEMU_IMG_BIN" cloud-localds ssh scp curl
    download_image
    create_overlay_if_needed
    write_cloud_init
    start_vm
    wait_for_ssh
    prepare_guest
    run_build_flow
    require_guest_launch_prereqs
    spawn_tmux_shells
    ;;
  stop)
    stop_vm
    ;;
  clean)
    reset_vm
    ;;
  -h | --help | help)
    usage
    ;;
  *)
    echo "Unknown action: $action" >&2
    usage >&2
    exit 1
    ;;
  esac
}

main "$@"
