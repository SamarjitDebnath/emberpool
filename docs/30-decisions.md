# Decisions

Design decisions, newest last. Related: [scope](00-scope.md) · [API](20-api.md)

## Firecracker microVMs, not containers
**Date:** 2026-11-27
**Decision:** Each sandbox is a Firecracker microVM under KVM with its own guest kernel, run under the jailer.
**Why:** Untrusted agent code must not share the host kernel. Firecracker is small, starts fast and supports snapshot restore.
**Rejected:** Containers and gVisor: they share or emulate the host kernel, a weaker boundary for hostile code.

## Snapshot once, restore per sandbox, never reuse
**Date:** 2026-11-27
**Decision:** Boot a template VM once with Python imported, snapshot it, restore one VM per run and destroy it afterwards.
**Why:** Restore skips kernel boot and interpreter start-up. One VM per run keeps runs from seeing each other's leftovers.
**Rejected:** Cold boot per run: too slow. Reusing VMs: leaks state between runs.

## Enforce and observe on the host
**Date:** 2026-11-27
**Decision:** Egress control, network trace and timeouts live on the host. The guest agent only carries code and output.
**Why:** Code in the sandbox can kill or lie to anything inside the guest, so guest-side controls prove nothing.
**Rejected:** Guest-side firewalling or logging.

## Name-based egress allowlist via our own resolver
**Date:** 2026-11-27
**Decision:** Default deny. The guest's DNS goes to an emberpool resolver that answers only allowlisted names; nftables allows only the IPs it returned and logs every verdict.
**Why:** The trace shows names, not bare IPs, and rules stay correct when CDNs rotate addresses.
**Rejected:** Static IP allowlists: break on CDN changes and give unreadable traces.

## vsock with length-prefixed frames
**Date:** 2026-11-27
**Decision:** Code and results travel over vsock port 1024 as 4-byte-length-prefixed JSON frames.
**Why:** Keeps the control channel off the guest network. Output routinely contains newlines. Listening sockets survive restore.
**Rejected:** Newline-delimited framing; a network-based channel.

## Swappable engine behind a protocol
**Date:** 2026-11-27
**Decision:** All Firecracker-specific code sits behind an `Engine` protocol (start, snapshot, restore, kill) in one private module.
**Why:** A faster implementation, such as Rust, could replace it later without touching the pool or the public API.
**Rejected:** Calling Firecracker directly from the pool.

## Guest kernel 6.1 with device-tree VMGenID
**Date:** 2026-11-27
**Decision:** Use the Firecracker CI 6.1 kernel (`CONFIG_VMGENID=y`), and refuse to start if the template VM does not have the `vmgenid` driver bound.
**Why:** Clones share one memory image, and VMGenID makes the guest kernel reseed its random number generator on restore. On aarch64 it needs device-tree support, which this build carries. Verified in the dev VM: two restores gave different `/dev/urandom` output; with the driver unbound they matched.
**Rejected:** Stock upstream 6.1: may lack device-tree VMGenID and silently repeat random output.

## Per-VM network namespace for restored clones
**Date:** 2026-11-27
**Decision:** Each restored VM gets its own network namespace holding a tap named `tap0` with a fixed MAC, identical addressing inside, and a unique veth uplink with masquerade.
**Why:** Clones share the snapshot's guest IP and MAC, so they only stay unambiguous on separate network stacks. The guest caches the template tap's MAC in ARP, so a tap with a new MAC breaks connectivity until a flush. Verified in the dev VM on Firecracker v1.18.0.
**Rejected:** `network_overrides` with a unique tap and subnet per VM, re-addressing the guest over vsock: connectivity would depend on guest code.

## v0.1 runs as root
**Date:** 2026-11-27
**Decision:** emberpool v0.1 must run as root on the host.
**Why:** The jailer needs root for chroot, uid/gid drop and cgroups, and per-VM namespaces, taps and nftables rules need `CAP_NET_ADMIN`. Each Firecracker process still drops privileges under the jailer.
**Rejected:** A privileged helper with an unprivileged library: safer, but too much to build for v0.1. Revisit later.

## Shared read-only rootfs plus a per-VM scratch drive
**Date:** 2026-11-27
**Decision:** All clones share one read-only root filesystem. Each VM gets a small sparse scratch drive as the guest's overlayfs upper layer, at the same path inside its jailer chroot.
**Why:** No per-VM rootfs copy, and the host can diff the scratch drive after teardown for the advisory file-change list.
**Rejected:** Full rootfs copy per VM: 512 MB each. tmpfs upper layer: the host cannot see file changes.

## One host resolver, policy in the root namespace
**Date:** 2026-11-27
**Decision:** One shared DNS resolver runs on the host. Each VM namespace only forwards DNS to it and masquerades traffic. Allow/drop rules and logging live in one root-namespace nftables table, keyed on each VM's veth, with one allow set per VM that the resolver fills.
**Why:** One log stream for the trace and one table to manage. The veth subnet tells the resolver which VM asked.
**Rejected:** A resolver and nftables table per namespace: N processes and N log streams.

## Versioned trace schema
**Date:** 2026-11-27
**Decision:** `trace.json` carries `schema_version` and an ordered list of `dns` events (name, answer or `NXDOMAIN`, time) and `conn` events (destination IP, port, protocol, resolved name if known, allowed or dropped, time).
**Why:** The trace is part of the public contract, so it needs a fixed, versioned shape before `TraceWriter` is written.
**Rejected:** Raw nftables log lines: unstable and hard to consume.

## Default network policy is deny
**Date:** 2026-11-27
**Decision:** A pool's default network policy is `"deny"`. PyPI and anything else must be allowlisted explicitly.
**Why:** Safe by default, and every allowed destination shows up in the caller's code.
**Rejected:** Allowing PyPI by default: convenient, but opens a path to an arbitrary-upload host without the caller asking.

## Fixed pool size in v0.1
**Date:** 2026-11-27
**Decision:** A pool keeps a fixed number of idle VMs, set by `size`.
**Why:** Predictable memory use and simpler code. Growing to a ceiling can be added later without changing the API.
**Rejected:** Autoscaling under load in v0.1.

## asyncio-only API
**Date:** 2026-11-27
**Decision:** The public API and the `Engine` protocol are async (asyncio). No blocking API in v0.1.
**Why:** Agents call tools concurrently, and the pool restores replacements in the background. A blocking wrapper can be added later.
**Rejected:** A sync API first, or both from the start.

## File transfer deferred to v0.2
**Date:** 2026-11-27
**Decision:** v0.1 runs code only. The request frame reserves an optional `files` field so v0.2 can add file transfer without a protocol change.
**Why:** Protects the v0.1 schedule while keeping the guest protocol stable.
**Rejected:** File transfer in v0.1.
