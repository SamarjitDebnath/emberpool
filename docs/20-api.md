# API

The public Python API.

Related: [scope](00-scope.md) · [setup](10-setup.md) · [decisions](30-decisions.md)

> **Planned, not implemented.** This page describes the target v0.1 API. Names and signatures may change before the first release.

## Public surface

Only these names, exported from `emberpool`, are public and stable once released:

| Name | What it is |
|---|---|
| `SandboxPool` | Owns the warm pool of restored VMs |
| `Sandbox` | One checked-out VM, used for a single run |
| `Result` | What a run returns: output, exit code and network trace |

Everything else, including modules whose names start with `_`, is internal.

## Example

```python
from emberpool import SandboxPool

async with SandboxPool(size=4, network="allow:pypi.org,files.pythonhosted.org") as pool:
    result = await pool.run("print(1 + 1)", timeout=10)
    print(result.exit_code, result.stdout)
    for event in result.trace:
        print(event)
```

## `SandboxPool`

Creating a pool builds the template VM (boot once, snapshot), then restores `size` VMs and keeps them idle.

- `size`: number of idle VMs kept ready. Fixed for the pool's lifetime in v0.1.
- `network`: egress policy for every sandbox in the pool.
  - `"deny"`: no network. The default.
  - `"allow:<name>,<name>,..."`: only these domain names resolve, and only connections to the addresses they resolved to are allowed.

`await pool.run(code, timeout=...)` checks out an idle VM, starts a replacement restore in the background, runs `code` in the guest, destroys the VM and returns a `Result`.

- `code`: Python source to run in the guest.
- `timeout`: wall-clock limit in seconds, enforced by the host killing the VM.

**When the pool is empty**, `run` waits for a replacement VM. `timeout` is one deadline that covers both the wait and the run:

- If no VM becomes idle before the deadline, `run` raises `TimeoutError` and no code ran. The message names the last restore error, if any.
- If the deadline passes while code is running, the host kills the VM and the `Result` has the timeout flag set.

A failed replacement restore is retried in the background with backoff; it never blocks other runs or restores. Callers waiting on an empty pool are served in arrival order.

`size` is the number of idle VMs, at most 128. VMs checked out for a run are extra, so many concurrent runs can hold more than `size` VMs at once.

**Startup fails closed.** Entering the pool raises if the template build, a network namespace, any of the first `size` restores, or the VMGenID check fails. The VMGenID check runs on a separate probe VM restored from the template, which is destroyed and never serves a run. Everything created up to that point is torn down before the error propagates.

**Sandbox.** `pool.checkout(timeout)` is an async context manager that yields one `Sandbox` (waiting up to `timeout` seconds for an idle VM). `await sandbox.run(code, timeout)` runs code once and destroys the VM; a second call raises. Leaving the block destroys the VM if it was not used. `pool.run` is `checkout` plus `run` under one deadline.

**Errors.** Argument errors raise `TypeError` or `ValueError` before a VM is taken. If the guest agent dies or sends a bad reply, `run` still returns a `Result` with the host trace, `exit_code` `-1`, empty stdout and an emberpool message in stderr. A timed-out run also has `exit_code` `-1`. If the host cannot produce a complete trace (the event stream failed, or the VM exceeded the per-run event cap), `run` raises instead of returning a partial trace. Calling `run` after the pool has closed raises `RuntimeError`.

File transfer (a `files` argument) is planned for v0.2.

The API is asyncio only; there is no blocking variant in v0.1. The pool is an async context manager. Leaving it destroys every VM and network namespace it created. The process must run as root.

## `Result`

| Field | Meaning | Trust |
|---|---|---|
| `stdout`, `stderr` | Output of the run | Reported by the guest; code can forge it |
| `exit_code` | Exit status | Reported by the guest; code can forge it |
| `trace` | DNS queries and connection verdicts, in order | Recorded on the host; complete |
| timeout flag | Whether the host killed the run | Recorded on the host |
| file changes | Files that differ after the run | Advisory; end state only |

Treat the host-recorded fields as evidence and the guest-reported fields as a convenience.

## Trace

The trace is also written as `trace.json`: a `schema_version` and an ordered list of events. There are two event types:

| Type | Fields |
|---|---|
| `dns` | time, queried name, answer (addresses) or `NXDOMAIN` |
| `conn` | time, destination IP, port, protocol, resolved name if known, `allowed` or `dropped` |

The schema is versioned; fields are only added within a major version.

## Behaviour callers can rely on

- Each `run` gets a fresh VM. Nothing persists between runs.
- `os.urandom` and `secrets` differ between sandboxes. Python's `random` module does not: every sandbox starts from the same snapshot, so seed it yourself if you need it to differ.
- With the default policy, all DNS lookups fail and all outbound connections are dropped.

## Guest protocol (internal)

Documented for contributors; not a public API.

The host reaches the guest agent over vsock, never the network. Firecracker exposes the guest's vsock as a Unix socket on the host:

```
host                                   guest agent (vsock port 1024)
connect <vm>.vsock
send  "CONNECT 1024\n"
recv  "OK <port>\n"
send  [4-byte length][JSON request]   ──▶  run code in a subprocess
recv  [4-byte length][JSON response]  ◀──  {stdout, stderr, exit_code}
```

Frames are length-prefixed, not newline-delimited, because output routinely contains newlines. The request reserves an optional `files` field for v0.2 file transfer; v0.1 agents ignore it. The agent's listening socket survives snapshot restore, so a restored VM is ready without relaunching it.
