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
| Host tools | `iproute2`, `nftables`, `curl`, `e2fsprogs` | Network setup needs `CAP_NET_ADMIN` |

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

The `resolv.conf` line lets `apk` reach the mirror during the build. `openrc` and the `inittab` line give a login on the serial console, which is useful for manual debugging. The emberpool guest agent will be baked into this image once it exists; at runtime the guest's DNS is pointed at emberpool's resolver.

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

## 6. Python environment

From the repository root:

```
uv sync
uv run python -c "import emberpool"
```

Always run Python through `uv run`.

## Networking requirements

Each sandbox gets its own network namespace containing:

- a tap device named `tap0` with the fixed MAC `02:ee:00:00:00:01` and address `172.16.0.1/30` (the guest is `172.16.0.2`)
- a veth pair to the host with a unique `/30` per sandbox (for example `10.200.N.0/30`)
- IP forwarding on, and an nftables masquerade rule for traffic leaving through the veth

The tap MAC must be the same for the template and every clone: the guest's ARP cache is part of the snapshot, and a tap with a different MAC gets no traffic until that cache is flushed. Creating namespaces, taps and nftables rules needs `CAP_NET_ADMIN`. See [decisions](30-decisions.md).

## Cleanup

Firecracker API sockets are created as `/tmp/fc-*.sock`. Remove any left behind after a run that creates VMs, along with any leftover network namespaces and veth devices.
