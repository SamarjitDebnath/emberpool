# Setup

How to build and run emberpool.

Related: [scope](00-scope.md) · [API](20-api.md) · [decisions](30-decisions.md)

## Requirements

| Component | Version | Notes |
|---|---|---|
| Host OS | Linux with KVM | `/dev/kvm` must exist and be accessible |
| Architecture | aarch64 | The only architecture verified so far |
| Firecracker | v1.18.0 | Single static binary, used with its jailer |
| Guest kernel | 6.1 LTS, `CONFIG_VMGENID=y` | Must support VMGenID through device tree; see below |
| Guest root filesystem | Alpine 3.20 + Python 3, ext4, 512 MB | |
| Python (host) | 3.12+ | Managed with `uv` |
| Host tools | `iproute2`, `nftables`, `curl`, `e2fsprogs` | |
| Privileges | root | v0.1 runs as root: the jailer and per-VM network setup need it |

### Developing on a Mac

Firecracker is Linux-only. On Apple Silicon (M3 or newer, macOS 15 or newer), run an Ubuntu VM with nested virtualization turned on and do everything inside it. `/dev/kvm` appears in that VM, but timings measured there are inflated by nesting and must not be reported as benchmark results.

## 1. Host access

```
ls -l /dev/kvm                    # crw-rw---- ... kvm
sudo usermod -aG kvm $USER        # then log out and back in
```

Building the root filesystem also uses Docker, so add yourself to the `docker` group as well.

## 2. Firecracker

Download the release for your architecture and keep the binaries outside the repository, for example in `~/fc`:

```
mkdir -p ~/fc && cd ~/fc
ARCH="$(uname -m)"
VER=v1.18.0
curl -L -o fc.tgz https://github.com/firecracker-microvm/firecracker/releases/download/${VER}/firecracker-${VER}-${ARCH}.tgz
tar -xzf fc.tgz
cp release-${VER}-${ARCH}/firecracker-${VER}-${ARCH} firecracker
cp release-${VER}-${ARCH}/jailer-${VER}-${ARCH} jailer
./firecracker --version
```

## 3. Guest kernel

Use a 6.1 kernel from Firecracker's CI artifacts. On aarch64 the file is a PE-format `Image`, not `vmlinux`, even though upstream names it `vmlinux-6.1.*`. Save it as `Image`.

```
file ~/fc/Image     # Linux kernel ARM64 boot executable Image
```

**VMGenID is required.** Every sandbox resumes from the same snapshot, and VMGenID is what makes the guest kernel reseed its random number generator on restore. On aarch64, Firecracker exposes VMGenID through device tree. Upstream Linux only added device-tree support to the VMGenID driver in later kernels; the Firecracker CI 6.1 build (verified on `6.1.188`) carries it. Check any kernel before using it:

1. The kernel was built with `CONFIG_VMGENID=y`.
2. Inside a booted guest, `ls /sys/bus/platform/drivers/vmgenid` lists a device such as `801ffff0.vmgenid`.

If the driver is not bound, clones of one snapshot produce identical `/dev/urandom` output. Do not use that kernel.

## 4. Root filesystem

Build a 512 MB ext4 image from Alpine with Python:

```
cd ~/fc
rm -f rootfs.ext4
dd if=/dev/zero of=rootfs.ext4 bs=1M count=512
mkfs.ext4 rootfs.ext4
sudo mkdir -p /tmp/rootfs && sudo mount rootfs.ext4 /tmp/rootfs
docker export $(docker create arm64v8/alpine:3.20) | sudo tar -xC /tmp/rootfs
echo "nameserver 1.1.1.1" | sudo tee /tmp/rootfs/etc/resolv.conf
sudo chroot /tmp/rootfs /sbin/apk add --no-cache python3 openrc
echo 'ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100' | sudo tee -a /tmp/rootfs/etc/inittab
sudo chroot /tmp/rootfs /bin/sh -c 'passwd -d root'
cd ~ && sudo umount /tmp/rootfs
```

The `resolv.conf` line lets `apk` reach the mirror during the build. `openrc` and the `inittab` line give a login on the serial console, which is useful for manual debugging. This plain image is only for the smoke test below; sandboxes need the guest image from step 6.

## 5. Smoke test

```
cd ~/fc
cat > vm.json <<'EOF'
{
  "boot-source": {"kernel_image_path": "Image", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"},
  "drives": [{"drive_id": "rootfs", "path_on_host": "rootfs.ext4", "is_root_device": true, "is_read_only": false}],
  "machine-config": {"vcpu_count": 1, "mem_size_mib": 512}
}
EOF
./firecracker --no-api --config-file vm.json
```

You should reach a `login:` prompt. Log in as `root`, run `python3 --version`, then `reboot` to exit.

## 6. Guest image

Sandboxes boot an image that carries the emberpool guest agent. Build it with the script in the repository (it needs root, Docker and `mkfs.ext4`; nothing is mounted on the host):

```
sudo scripts/build-rootfs.sh ~/fc/emberpool-rootfs.ext4
```

The image mounts an overlay with its upper layer on the per-VM scratch drive, brings up `eth0` as `172.16.0.2`, points DNS at `172.16.0.1` and keeps the agent listening on vsock port 1024. The script's header describes the boot sequence in full.

## 7. Python environment

From the repository root:

```
uv sync
uv run python -c "import emberpool"
```

Always run Python through `uv run`.

Tell emberpool where the files are, either with a `Settings` object or with environment variables (see [API](20-api.md)):

```
export EMBERPOOL_FIRECRACKER=$HOME/fc/firecracker
export EMBERPOOL_JAILER=$HOME/fc/jailer
export EMBERPOOL_KERNEL=$HOME/fc/Image
export EMBERPOOL_ROOTFS=$HOME/fc/emberpool-rootfs.ext4
```

The process that runs the pool must be root.

## Networking requirements

Each sandbox gets its own network namespace containing:

- a tap device named `tap0` with the fixed MAC `02:ee:00:00:00:01` and address `172.16.0.1/30` (the guest is `172.16.0.2`)
- a veth pair to the host with a unique `/30` per sandbox (for example `10.200.N.0/30`)
- IP forwarding on, and an nftables masquerade rule for traffic leaving through the veth
- an nftables rule forwarding the guest's DNS to emberpool's shared resolver on the host

The tap MAC must be the same for the template and every clone: the guest's ARP cache is part of the snapshot, and a tap with a different MAC gets no traffic until that cache is flushed.

Allow/drop rules and logging are not in the namespace. They live in one emberpool nftables table in the host's root namespace, matched on each sandbox's veth, with one allow set per sandbox. See [decisions](30-decisions.md).

emberpool turns on `net.ipv4.ip_forward` for the whole host.

### Hosts with another firewall (for example Docker)

emberpool refuses to start if another firewall table would drop forwarded sandbox traffic after emberpool's own table accepts it. Docker sets the `FORWARD` policy to drop, so on a Docker host add two accept rules for emberpool's uplinks first, where `<prefix>` is the `Settings.prefix` (`ep` by default):

```
sudo iptables -I DOCKER-USER -i <prefix>-h+ -j ACCEPT
sudo iptables -I DOCKER-USER -o <prefix>-h+ -j ACCEPT
```

emberpool's own table still drops every connection that is not on a sandbox's allowlist. These rules are not persistent across reboots unless you save them. emberpool never adds or changes rules it does not own.

## Disk layout per sandbox

All sandboxes share one read-only `rootfs.ext4`. Each sandbox also gets a sparse copy of the template's scratch drive, taken after the template was paused, which the guest uses as its overlayfs upper layer, so writes never touch the shared image. A freshly formatted drive would not work: the guest kernel's view of that filesystem is part of the snapshot. Both drives must appear at the same paths inside every sandbox's jailer chroot, because the snapshot records them. After teardown the host reads the scratch drive with userspace tools (never by mounting it) to produce the advisory file-change list.

## Cleanup

Firecracker API sockets are created as `/tmp/fc-*.sock`. Remove any left behind after a run that creates VMs, along with any leftover network namespaces and veth devices.
