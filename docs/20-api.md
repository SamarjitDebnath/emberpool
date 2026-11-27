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

- `size`: number of idle VMs kept ready. Whether the pool can grow under load is an open question.
- `network`: egress policy for every sandbox in the pool.
  - `"deny"`: no network. The default.
  - `"allow:<name>,<name>,..."`: only these domain names resolve, and only connections to the addresses they resolved to are allowed.

`await pool.run(code, files=None, timeout=...)` checks out an idle VM, starts a replacement restore in the background, runs `code` in the guest, destroys the VM and returns a `Result`.

- `code`: Python source to run in the guest.
- `files`: files to place in the guest before running. May move to v0.2.
- `timeout`: wall-clock limit in seconds, enforced by the host killing the VM.

The pool is an async context manager. Leaving it destroys every VM and network namespace it created.

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

The trace is also written as `trace.json`. Each entry is either a DNS query (name, answer or `NXDOMAIN`) or a connection attempt (destination, port, allowed or dropped). Connections are shown with the name that was resolved for them when there is one.

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

Frames are length-prefixed, not newline-delimited, because output routinely contains newlines. The agent's listening socket survives snapshot restore, so a restored VM is ready without relaunching it.
