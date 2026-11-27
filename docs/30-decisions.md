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
