# Scope

What emberpool does and does not do.

Related: [setup](10-setup.md) · [API](20-api.md) · [decisions](30-decisions.md)

## Status

Pre-alpha. The architecture below is designed and partly verified by hand; the library itself is not implemented yet. Any number marked `TARGET` is a goal, not a measurement.

## What it is

A Python library that gives an AI agent a disposable Linux microVM for each piece of code it runs, and a record of what that code tried to do over the network.

- **Isolation by a real VM.** Each sandbox is a Firecracker microVM under KVM with its own guest kernel. Untrusted code never shares the host kernel.
- **Fast checkout from a warm pool.** A template VM is booted once and snapshotted with Python already imported. Sandboxes are restored from that snapshot and kept idle until needed. `TARGET`: restore under 50 ms on bare metal.
- **One sandbox per run.** A VM is destroyed after a single run, never reused, so nothing from one run reaches the next.
- **Network audit trail.** Every DNS query and every connection verdict is recorded on the host and returned with the result.
- **Default-deny egress.** Code has no network unless the caller allowlists domain names.

## How it works

```
  your agent ── await pool.run(code) ──▶ emberpool (host, Python)
                                            │ restore from snapshot
                                            ▼
                                     Firecracker microVM (guest)
                                       own kernel · 1 vCPU · 512 MiB
                                       agent listening on vsock
```

1. **Build once.** At pool startup, boot a template VM from the kernel and root filesystem, wait until the in-guest agent reports ready, then snapshot memory and device state.
2. **Restore many.** Each sandbox gets a fresh jailer chroot, a fresh scratch drive on top of the shared read-only root filesystem, and a fresh network namespace, then loads the snapshot. Restored VMs wait idle in the pool.
3. **Run.** The caller checks out an idle VM, a replacement restore starts in the background, and code goes to the guest over vsock. Results come back the same way.
4. **Tear down.** The VM is killed, its network namespace deleted, and the trace returned to the caller.

## Trust model

Everything the sandbox cannot be trusted to report honestly is enforced and observed on the host. The in-guest agent is a convenience, not a control: code in the sandbox can kill it or lie to it, which only costs the caller their own result.

| Guarantee | Enforced by | Can guest code defeat it? |
|---|---|---|
| Code cannot reach the host kernel | Firecracker + KVM, separate guest kernel | No |
| VMM process is confined | Jailer: chroot, uid/gid drop, seccomp, cgroups | No |
| Egress limited to the allowlist | nftables on the host side of the VM's tap | No |
| Network trace is complete | nftables logging and DNS resolver, both on the host | No |
| Wall-clock timeout | Host kills the VM process | No |
| Filesystem change list | Host reads the VM's scratch drive after teardown, in userspace, never mounted | Partially; advisory only |
| stdout / stderr accuracy | Agent inside the guest | Yes; convenience only |

## Networking

- Each VM runs in its own network namespace with identical inside addressing, so clones of one snapshot never clash. See [decisions](30-decisions.md).
- The VM's DNS goes to one resolver run by emberpool on the host, shared by all sandboxes. It logs every query and only resolves allowlisted names; everything else gets `NXDOMAIN`.
- nftables on the host allows connections only to IPs the resolver returned for that sandbox's allowlisted names, logs every verdict, and drops the rest. All policy lives in one host table with one allow set per sandbox; each namespace only forwards DNS and masquerades.
- The default policy is deny. Every allowed destination must be named by the caller. Allowlisting names rather than IPs keeps rules correct when CDNs rotate addresses, and makes the trace read `pypi.org` instead of a bare IP.
- Code and results travel over vsock, never over the network.

## Not in scope

- Multi-host scheduling, clustering or persistence between runs. One host, one fixed-size pool.
- A blocking (sync) API. v0.1 is asyncio only.
- File transfer into or out of the sandbox. Planned for v0.2.
- Running without root. v0.1 must run as root on the host.
- Long-lived or interactive sandboxes. A sandbox lives for one run.
- Non-Linux hosts. Firecracker needs Linux with KVM. On a Mac, run inside a Linux VM with nested virtualization, for development only.
- GPU access.
- A complete record of filesystem activity (see limitations).

## Known limitations

- **Repeated application state.** Every clone resumes from the same memory image. The guest kernel reseeds its random number generator on restore (VMGenID), so `os.urandom` and `secrets` are safe. Python's `random` module is not: imported before the snapshot, `random.random()` returns the same sequence in every sandbox. Do not use it for anything that must differ between runs.
- **VMGenID depends on the guest kernel build.** On aarch64 the reseed needs a kernel whose VMGenID driver supports device tree. The supported kernel is verified; a different kernel may silently lose the reseed. emberpool will refuse to start if the template VM does not have the driver bound.
- **Filesystem auditing is advisory.** The guest kernel owns the block device. The post-run file list shows end state only and misses files created and then deleted. The host never mounts the guest's disk; it reads it with userspace tools under size and entry limits.
- **Architecture.** Developed and verified on aarch64 only so far.
- **Performance numbers.** Development runs in a nested-virtualization VM, where timings are inflated 2 to 3x. Those timings are never published as benchmarks.

## Open questions

- CPU and memory limits per sandbox: defaults to be chosen once the pool runs.
- Whether the jailer's `--netns` option works as needed with snapshot restore. Untested.
- Growing the pool under load, and a privileged helper so the library need not run as root: both after v0.1.
