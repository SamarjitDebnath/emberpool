#!/usr/bin/env bash
# Build the emberpool guest root filesystem: Alpine 3.20 + python3 + the
# emberpool guest agent, as a 512 MB ext4 image.
#
# Usage:  sudo scripts/build-rootfs.sh OUTPUT.ext4
#
# Needs root (file ownership in the image), docker and mkfs.ext4 with -d
# (e2fsprogs 1.43 or newer). The image is assembled in a directory and written
# with `mkfs.ext4 -d`; nothing is mounted on the host. Set EP_DEBUG_CONSOLE=1
# to add a passwordless root login on the serial console for manual debugging.
#
# What the image does at boot
# ---------------------------
# /sbin/init is /sbin/ep-init, which runs as PID 1:
#   1. mounts the scratch drive /dev/vdb (ext4) at /mnt/scratch;
#   2. mounts overlayfs on /mnt/root: lower = the read-only root, upper and
#      work = directories on the scratch drive;
#   3. pivots into the overlay and execs busybox init.
# If any step fails the guest powers off, so it never runs on a writable
# shared root and the agent never becomes ready (fail closed).
# Busybox init then runs `ep-init --sysinit` (loopback, hostname, and eth0 as
# 172.16.0.2/30 via 172.16.0.1 if the VM has a network interface) and keeps
# the agent running: `python3 -B /opt/emberpool/agent.py`, respawned if killed.
#
# What the engine must provide
# ----------------------------
# - Boot args including `console=ttyS0 reboot=k panic=1 pci=off`.
# - Drive 1 (vda): this image, root device, read-only. Shared by every VM.
# - Drive 2 (vdb): the scratch drive, read-write, an ext4 filesystem made on
#   the host (for example `truncate -s 64M s.ext4 && mkfs.ext4 -q s.ext4`).
#   A clone restored from a snapshot must get a byte copy of the *template's*
#   scratch image, taken after the template was paused: the guest kernel's
#   view of that filesystem is part of the snapshot, so a freshly formatted
#   drive would not match it.
# - A vsock device; the agent listens on port 1024.
#
# Readiness
# ---------
# The agent is ready when a vsock CONNECT to port 1024 succeeds. The engine
# waits with emberpool.exec_client.wait_ready(vsock_uds_path, timeout), which
# connects and closes without sending a request. The agent also prints
# "emberpool-agent: ready" to the serial console.

set -euo pipefail

ALPINE_IMAGE="alpine:3.20"
IMAGE_SIZE="512M"

if [[ $# -ne 1 ]]; then
    echo "usage: $0 OUTPUT.ext4" >&2
    exit 2
fi
out="$1"
if [[ "$(id -u)" -ne 0 ]]; then
    echo "$0: run as root (for example with sudo)" >&2
    exit 1
fi
command -v docker >/dev/null || { echo "$0: docker not found" >&2; exit 1; }
command -v mkfs.ext4 >/dev/null || { echo "$0: mkfs.ext4 not found" >&2; exit 1; }

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
guest_src="$repo/src/emberpool/guest"
for f in agent.py _protocol.py; do
    [[ -f "$guest_src/$f" ]] || { echo "$0: missing $guest_src/$f" >&2; exit 1; }
done
if ! cmp -s "$guest_src/_protocol.py" "$repo/src/emberpool/_protocol.py"; then
    echo "$0: guest/_protocol.py differs from emberpool/_protocol.py; re-copy it" >&2
    exit 1
fi

case "$(uname -m)" in
    aarch64 | arm64) platform="linux/arm64" ;;
    x86_64) platform="linux/amd64" ;;
    *) echo "$0: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

work="$(mktemp -d /tmp/ep-rootfs.XXXXXX)"
container=""
cleanup() {
    if [[ -n "$container" ]]; then
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

stage="$work/stage"
root="$work/root"
mkdir -p "$stage/opt/emberpool" "$stage/sbin" "$root"
cp "$guest_src/agent.py" "$guest_src/_protocol.py" "$stage/opt/emberpool/"

# --- /sbin/ep-init ----------------------------------------------------------
cat >"$stage/sbin/ep-init" <<'EOF'
#!/bin/sh
# emberpool guest init. As PID 1: put an overlay (upper layer on the scratch
# drive /dev/vdb) over the read-only root and hand over to busybox init.
# With --sysinit: early setup, run by busybox init from /etc/inittab.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$1" = "--sysinit" ]; then
    mount -t sysfs sysfs /sys 2>/dev/null
    mkdir -p /dev/pts /dev/shm
    mount -t devpts devpts /dev/pts 2>/dev/null
    mount -t tmpfs -o nosuid,nodev,mode=1777 tmpfs /dev/shm 2>/dev/null
    hostname -F /etc/hostname 2>/dev/null
    ip link set lo up
    if [ -e /sys/class/net/eth0 ]; then
        ip addr add 172.16.0.2/30 dev eth0 &&
            ip link set eth0 up &&
            ip route add default via 172.16.0.1
    fi
    exit 0
fi

fail() {
    echo "ep-init: $*; powering off" >/dev/console
    sync
    reboot -f
    exit 1
}

mount -t proc proc /proc || fail "cannot mount /proc"
mount -t devtmpfs devtmpfs /dev 2>/dev/null # may already be mounted by the kernel
[ -b /dev/vdb ] || fail "no scratch drive /dev/vdb"
mount -o remount,ro / 2>/dev/null
mount -t ext4 -o nosuid,nodev /dev/vdb /mnt/scratch || fail "cannot mount scratch drive"
mkdir -p /mnt/scratch/upper /mnt/scratch/work || fail "cannot prepare scratch drive"
mount --bind / /mnt/lower || fail "cannot bind the root filesystem"
mount -t overlay overlay \
    -o lowerdir=/mnt/lower,upperdir=/mnt/scratch/upper,workdir=/mnt/scratch/work \
    /mnt/root || fail "cannot mount the overlay"
mount --move /dev /mnt/root/dev || fail "cannot move /dev"
mount --move /proc /mnt/root/proc || fail "cannot move /proc"
cd /mnt/root || fail "cannot enter the overlay"
pivot_root . oldroot || fail "pivot_root failed"
exec chroot . /bin/sh -c 'umount -l /oldroot; exec /bin/busybox init' \
    </dev/console >/dev/console 2>&1
EOF

# --- /etc/inittab -----------------------------------------------------------
mkdir -p "$stage/etc"
cat >"$stage/etc/inittab" <<'EOF'
::sysinit:/sbin/ep-init --sysinit
::respawn:/usr/bin/python3 -B /opt/emberpool/agent.py
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/sync
EOF
if [[ "${EP_DEBUG_CONSOLE:-0}" == "1" ]]; then
    echo 'ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100' >>"$stage/etc/inittab"
fi

# --- Alpine + python3 in a container ----------------------------------------
container="$(docker create --platform "$platform" "$ALPINE_IMAGE" /bin/sh -c '
    set -e
    apk add --no-cache python3
    chown -R root:root /opt/emberpool /sbin/ep-init /etc/inittab
    chmod 0755 /opt/emberpool /sbin/ep-init
    chmod 0644 /opt/emberpool/agent.py /opt/emberpool/_protocol.py /etc/inittab
    ln -sf /sbin/ep-init /sbin/init
    passwd -d root >/dev/null
    python3 -m compileall -q /opt/emberpool
    python3 -m compileall -q -j 0 /usr/lib/python3* >/dev/null 2>&1 || true
')"
docker cp "$stage/." "$container:/"
docker start -a "$container"
docker export "$container" | tar -x --numeric-owner -C "$root"

# Files docker manages at runtime; write their final contents here.
echo "nameserver 172.16.0.1" >"$root/etc/resolv.conf"
echo "sandbox" >"$root/etc/hostname"
printf '127.0.0.1\tlocalhost\n::1\tlocalhost\n' >"$root/etc/hosts"
rm -f "$root/.dockerenv"
mkdir -p "$root/mnt/lower" "$root/mnt/scratch" "$root/mnt/root" "$root/oldroot"

rm -f "$out"
truncate -s "$IMAGE_SIZE" "$out"
mkfs.ext4 -q -F -L emberpool-root -d "$root" "$out"
if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown "$SUDO_UID:$SUDO_GID" "$out"
fi
echo "built $out"
