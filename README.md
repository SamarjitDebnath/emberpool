# emberpool

Fast, auditable Firecracker microVM sandboxes for AI agent code. Warm pool, own kernel, network audit trail.

emberpool is a Python library that gives an AI agent a disposable Linux microVM for each piece of code it runs, and a host-recorded log of what that code tried to do over the network.

```python
from emberpool import SandboxPool

async with SandboxPool(size=4, network="allow:pypi.org,files.pythonhosted.org") as pool:
    result = await pool.run(
        "import socket; socket.create_connection(('pypi.org', 443)); print('reached pypi')",
        timeout=60,  # one deadline: waiting for a free VM plus the run itself
    )
    print(result.exit_code, result.stdout)
    for event in result.trace:          # DNS queries and connection verdicts, seen by the host
        print(event)
```

> **Status: pre-alpha.** v0.1 is implemented and runs end to end on an aarch64 development host. It has not been run on bare metal or released, and the API may still change. Performance targets are unmeasured; timings from the nested-virtualization development VM are not benchmarks.

## Why

Agents run code they wrote a moment ago, and sometimes code someone tricked them into writing. emberpool is built around three ideas:

- **A real VM boundary.** Each run gets its own Firecracker microVM under KVM with its own guest kernel, launched through Firecracker's jailer. Untrusted code never shares the host kernel.
- **Speed from snapshots.** A template VM is booted once, with the in-guest agent running, and snapshotted. Sandboxes are restored from it and kept warm, so a run does not pay for a kernel boot. Each run starts a fresh `python3` process inside its VM, and every VM is destroyed after one run.
- **Evidence, not self-reporting.** Network policy and the trace live on the host. The sandbox cannot hide a DNS lookup or a connection attempt, because the guest is never asked.

## How it works

```
  your agent ── await pool.run(code) ──▶ emberpool (host, Python, root)
                                            │ restore from snapshot
                                            ▼
                                     Firecracker microVM, jailed
                                       own kernel · 1 vCPU · 512 MiB
                                       agent on vsock · own netns
```

1. **Build once.** Boot a template VM, wait for the in-guest agent, snapshot memory and state.
2. **Restore many.** Each sandbox gets a fresh jail, a fresh scratch drive over a shared read-only root filesystem, and its own network namespace, then loads the snapshot.
3. **Run.** Code goes to the guest over vsock. A replacement VM is restored in the background.
4. **Tear down.** The VM is killed, its namespace deleted, and the host's trace returned with the result.

Networking is deny-by-default. When you allowlist domain names, emberpool's own DNS resolver answers only those names, and nftables on the host admits connections only to the addresses it returned. Every query and every verdict is logged.

## What you can trust in a `Result`

| Field | Source | Trust |
|---|---|---|
| `trace` | Host resolver and nftables | Complete; the guest cannot alter it |
| `timed_out` | Host | The host killed the VM |
| `file_changes` | Host reads the scratch drive (never mounts it) | Advisory; end state only |
| `stdout`, `stderr`, `exit_code` | Guest agent | Convenience; code in the sandbox can forge them |

## Requirements

- Linux with KVM (`/dev/kvm`), **aarch64**. Other architectures are not verified yet.
- Firecracker v1.18.0 and its jailer.
- A 6.1 guest kernel with device-tree VMGenID support, so restored clones get fresh randomness. See [setup](docs/10-setup.md) for how to check.
- Python 3.12+ and [uv](https://docs.astral.sh/uv/).
- `iproute2`, `nftables`, `e2fsprogs`, and Docker to build the guest image.
- **Root.** v0.1 must run as root: the jailer and per-sandbox networking need it. Each Firecracker process still drops privileges inside its jail.

On a Mac, develop inside a Linux VM with nested virtualization (Apple M3 or newer, macOS 15 or newer). It works, but it is slow, and its timings mean nothing.

## Quick start

From the repository root on the Linux host:

```bash
make setup        # install the venv, fetch Firecracker + jailer into ~/fc, check the host
# put the 6.1 guest kernel at ~/fc/Image (see docs/10-setup.md)
make rootfs       # build the guest image with the emberpool agent (root + Docker)
make check        # confirm everything is in place
make run CODE='print(1 + 1)'
make run CODE='import socket; socket.create_connection(("pypi.org", 443))' NETWORK=allow:pypi.org
```

`make run` prints the guest's stdout, then the exit code, file changes and network trace on stderr.

**Docker hosts:** Docker's firewall drops forwarded traffic, and emberpool refuses to start rather than run with networking it cannot vouch for. `make firewall-allow` adds the two accept rules it needs for the default `ep` prefix. This changes the host firewall; read [setup](docs/10-setup.md) first. The rules do not survive a reboot.

### Configuration

The library finds its files through `Settings`, or `EMBERPOOL_*` environment variables for any field left unset:

```python
from pathlib import Path
from emberpool import SandboxPool, Settings

settings = Settings(rootfs=Path("/srv/emberpool/rootfs.ext4"))  # the rest from EMBERPOOL_*
async with SandboxPool(size=2, settings=settings) as pool:
    ...
```

Required: `EMBERPOOL_FIRECRACKER`, `EMBERPOOL_JAILER`, `EMBERPOOL_KERNEL`, `EMBERPOOL_ROOTFS`. Full table in the [API reference](docs/20-api.md).

## Make targets

| Target | What it does |
|---|---|
| `make setup` | Install dependencies, fetch Firecracker, check the host |
| `make check` | Read-only check that the host has everything |
| `make rootfs` | Build the guest image with the agent |
| `make test` | Unit tests, no root; VM tests skip |
| `make vm-test` | Only the tests that boot real VMs, as root |
| `make test-all` | Every test, as root, then a leftover check |
| `make run CODE=... NETWORK=... TIMEOUT=...` | Run code in a fresh sandbox |
| `make leftovers` | List sockets, namespaces, links, tables or processes a run left behind |
| `make firewall-show` / `firewall-allow` | Inspect or open Docker's `DOCKER-USER` chain for sandbox uplinks |
| `make clean` / `distclean` | Remove caches; also the venv |

Override paths on the command line, for example `make vm-test FC_DIR=/opt/fc`. `make` alone lists everything.

## Project layout

```
src/emberpool/
  __init__.py        public API: SandboxPool, Sandbox, Result, Settings
  pool.py            warm pool, checkout, replacement, timeouts
  engine.py          Engine / NetPolicy / ExecClient protocols
  _firecracker.py    Firecracker engine (the only module that knows Firecracker)
  _jailer.py         jail setup
  netpolicy.py       per-VM namespaces, taps, host nftables table
  _resolver.py       allowlisting DNS resolver
  trace.py           host trace from nftables logs and DNS events
  exec_client.py     host side of the vsock protocol
  guest/agent.py     runs inside the VM (standard library only)
scripts/
  build-rootfs.sh    guest image builder
  run.py             one-shot runner used by `make run`
docs/                scope, setup, API, decisions, engineering rules
```

## Documentation

- [Scope](docs/00-scope.md): what emberpool does and does not do, trust model, limitations
- [Setup](docs/10-setup.md): host, kernel, guest image, networking, firewall
- [API](docs/20-api.md): `SandboxPool`, `Sandbox`, `Result`, `Settings`, trace format
- [Decisions](docs/30-decisions.md): design choices and what was rejected
- [Engineering rules](docs/40-rules.md): the safety rules every change follows

## Known limitations

- Single host, one fixed-size pool per host: a second pool on the same host refuses to start. No clustering or persistence between runs.
- asyncio only; no blocking API in v0.1.
- No file transfer into or out of the sandbox yet (planned for v0.2).
- The file-change list shows end state only and misses files created and then deleted. It relies on the guest flushing its disk before replying, so code in the sandbox can hide changes from it.
- Verified on aarch64 only.

## Contributing

Read [docs/40-rules.md](docs/40-rules.md) before changing code. The guest is treated as hostile, isolation fails closed, host commands never go through a shell, and every resource has a teardown. A change that breaks a rule is wrong even if its tests pass. Run `make test-all` and `make leftovers` before sending a change.

## License

[MIT](LICENSE)
