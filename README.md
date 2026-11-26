# Treasury Project — Student Starter

This is the common starting point for the Treasury Project. It provides a runnable TCP server/client baseline, length-prefixed JSON messaging, configuration, logging, command-line parsing, and shared serialization/hash helpers.

It deliberately does **not** implement the assessed cryptographic protocols. Complete the `TODO` sections in the milestone modules and keep private values in the owning program's files.

## Requirements

- Python 3.10+
- `cryptography`
- `ecdsa` (needed only if you implement optional attack A2)
- Wireshark for the required captures

Install:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Before running

1. Set `GROUP` in `config.py` to all group members' student IDs, sorted numerically and joined with `-`.
2. Agree on the same `GROUP` value across every machine/program.
3. Read `docs/IMPLEMENTATION_CHECKLIST.md` and the project Overview/Milestones supplied by the instructor.

## Run the baseline connection

Terminal 1:

```bash
python -m treasury.server --name server
```

Terminal 2:

```bash
python -m treasury.member --name M1
```

The member sends a baseline `hello` message and the server logs and acknowledges it. This is **only a transport smoke test**; it is not the secure channel, certificate validation, login, or signed-request protocol required by Milestone 1.

Stop either program with Ctrl+C.

## Project layout

```text
treasury/
  config.py          Shared project parameters
  encoding.py        Canonical JSON and project hash H
  logging_utils.py   Consistent console + per-program file logs
  framing.py         4-byte big-endian length-prefixed JSON over TCP
  network.py         Small reusable TCP server/client helpers
  certificates.py    Certificate data model and TODOs
  channel.py         Milestone 1 ECDH/handshake/AES-GCM TODOs
  login.py           Milestone 1 proof-of-knowledge login TODOs
  requests.py        Milestone 1 signed request/replay protection TODOs
  sharing.py         Milestone 2 Shamir sharing/commitment TODOs
  opening.py         Milestone 2 verifiable decryption TODOs
  voting.py          Milestone 3 encrypted ballot TODOs
  server.py          Runnable baseline server
  member.py          Runnable baseline member
  founder.py         Founder setup entry point (TODO)
  mallory.py         Attack harness entry point (TODO)
```

## Important rules

- Use `secrets`, never `random`, for cryptographic randomness.
- Never log private keys, login secrets, Shamir shares, or plaintext vault keys.
- Keep each program's private values in its own data directory. Do not read another program's private files.
- Use `--weak <name>` only when demonstrating the corresponding deliberately weakened implementation. With no `--weak` option, run the secure implementation.
- The default listener is `127.0.0.1:5050`. Mallory's proxy should listen on port `6000` when you implement A1.
- The transport smoke test sends JSON in cleartext. Do not mistake it for the encrypted channel required by Milestone 1.
- Add tests as you implement each protocol. Do not rely only on a successful demo run.

## Weakness names reserved by the specification

| Attack | CLI weakness name | Status |
|---|---|---|
| A1 unsigned handshake | `unsigned-handshake` | Mandatory |
| A2 reused signing nonce | `fixed-nonce` | Optional bonus |
| A3 short login challenge | `short-challenge` | Optional bonus |
| A4 replayed non-interactive login | `no-nonce` | Optional bonus |
| A5 missing decryption proof | `no-proof` | Mandatory |
| A6 missing share check | `no-share-check` | Optional bonus |
| A7 unsigned ballots | `unsigned-ballots` | Optional bonus |

## Tests

```bash
python -m unittest discover -s tests -v
```
