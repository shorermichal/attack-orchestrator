# Attack Orchestrator

Picks the right multi-stage attack for a mobile device, runs it, and pulls
files off the device once it succeeds. Three parts: a Python framework, a C
device simulator it talks to over TCP, and tests (including tests that run
against the real simulator).

## Setup

```
cd device_simulator && make && cd ..

python3 -m venv .venv
.venv/bin/pip install pytest
.venv/bin/python -m pytest -q
```

## How it works

1. Given a device (model, iOS version, battery, ...) and a list of attacks,
   a **selector** filters out attacks that don't fit, then picks the best of what's left.
2. An **orchestrator** runs the chosen attack's **stages** one at a time.
   Each stage can succeed or fail; the first failure stops the chain.
3. If every stage succeeds, the orchestrator returns a **session** - the
   only way to read files off the device.
4. An **extractor** uses that session to pull one file, or a checklist of
   files, to disk.

## Design decisions (Part 1 - the framework)

**Picking an attack when several fit.** Filter to attacks whose
requirements match the device, then rank by estimated success probability
(each stage's odds multiplied together), tie-broken by an explicit
priority. This lives behind a swappable `AttackSelector` interface rather
than one hardcoded rule, since "how do you pick?" is a judgment call, not a
fixed answer.

**Checking device state before running.** Each attack declares
`Requirements`: model, iOS version range, minimum battery, jailbroken state.
Every field defaults to "don't care," so an attack only states what
actually matters to it.

**A failed stage kills the whole chain.** No retry, no automatic fallback to
another attack. A failed real exploit attempt can change device state (trip
a security counter, force a reboot, burn a one-shot bug), so retrying
automatically isn't safe to assume - the caller sees exactly what happened
and decides whether to try again.

**A dropped connection is not the same as a failed stage.** One is bad
luck, the other is infrastructure breaking. They're reported separately, so
the simulator's ability to drop mid-chain (Part 2) fits naturally instead of being conflated with "the exploit didn't work."

**Extraction only works through a completed session.** `Extractor` needs a
`DeviceSession`, and the only way to get one is a fully successful attack
run - enforced by the type, not by convention. "Extract everything" means a
checklist of known file paths, since the device only ever offers "read this
one path," never "list what's here."

## The protocol (Part 2 - the device simulator)

Plain text over TCP: one line per command, one line per reply - except a
successful `READ`, which is followed by exactly `<length>` raw bytes, so
binary content (or text with embedded newlines) still comes through
byte-exact.

| Client sends | Server replies |
|---|---|
| `INFO` | `INFO <device_id> <model> <ios_version> <battery_percent> <jailbroken:0/1>` |
| `STAGE <name> <probability> <is_last:0/1>` | `SUCCESS` / `FAILURE` - or the connection just closes, simulating a drop |
| `READ <path>` | `OK <length>` + raw bytes, or `ERR locked` / `ERR not_found` |
| `QUIT` | connection closes |

The **server** rolls the dice for each stage, not the client - on a real
device, whether an exploit lands is the device's behavior, not something
the attacker's laptop gets to decide. It also enforces the lock itself:
`READ` only succeeds once the server has personally seen a stage marked
`is_last` succeed, so the client's claim of "I finished the chain" is never
just taken on faith. Connection drops are triggered deterministically
(`--drop-on-stage NAME`, so tests are repeatable, not flaky) and surface to
the framework as a distinct `DeviceConnectionError` rather than a failed
stage.

## Tests (Part 3)

```
.venv/bin/python -m pytest -q                       # everything
.venv/bin/python -m pytest -q -m "not integration"   # fast, no subprocess
```

`test_selection.py`, `test_orchestrator.py`, and `test_extraction.py` are
fast unit tests against an in-memory fake device. `test_integration.py`
runs the same framework against the real, compiled `device_simulator` binary
over a real socket (it builds and launches it via a `simulator` fixture) -
covering the full unlock-then-read path, the lock actually being enforced by
the server rather than the orchestrator, a dropped connection mid-chain, and
a byte-exact read through embedded newlines.
