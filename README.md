# Cryptographic Treasury System

ICS505, German International University. Extended from the official Treasury Student
Starter Project. GROUP: `16002216-16003727-16004417-16005162`. Submission: 12 December 2026.

John's channel implementation is available. Login, signed treasury requests, ledger,
vault and voting remain integration work; a successful channel probe is **not login**.
No Streamlit dashboard is implemented.

## Architecture and ownership

| Owner | Modules and responsibilities |
|---|---|
| John | Configuration, identity/certificates, TCP framing, authenticated ECDH, AES-GCM, logging, local A1, CI and integration |
| Essam | `login.py`, `requests.py`, registration, both Schnorr logins, signed requests, sequence persistence, ledger, Wireshark evidence |
| Divan | `sharing.py`, `opening.py`, founder vault extension, threshold decryption/proofs, A5 |
| Yassin | `voting.py`, signed spending requests/ballots, homomorphic total, bonus A7 |

Founder signs public keys published by independently executed server/member programs.
Members connect to `127.0.0.1:5050`; Mallory listens only on `127.0.0.1:6000`.
The three handshake messages are JSON. Subsequent application JSON is AES-256-GCM
protected inside the existing four-byte length framing. No HTTP or web framework is used.
The original `network.py` cleartext helpers remain for compatibility; the secure CLIs
use `channel.py` and `framing.py` directly.

Python >=3.10, `cryptography`, and standard-library `secrets`, `socket`, `json`,
`hashlib`, `logging` and `unittest` are the stack. Shared modular parameters use the
[RFC 3526 section 3 prime](https://www.rfc-editor.org/rfc/rfc3526#section-3), with
`q=(p-1)//2` and assignment generator `g=4`.

## Installation

Run from the folder containing this README and `treasury/` (the supplied archive has
an extra outer `Treasury_Starter_Project` folder).

```powershell
python -m venv .venv-john
.\.venv-john\Scripts\Activate.ps1
python -m pip install -r requirements-lock.txt
python -m unittest discover -s tests -v
```

On Linux/macOS use `source .venv-john/bin/activate`. The lock file reproduces John's
tested dependencies; `requirements.txt` lists the compatible dependency range.
The old supplied `.venv` references a missing Python installation; use the new environment.
Tests bind ports 5050 and 6000, so stop running demo servers before testing.

## Fresh owner-local setup

Run the following as separate program executions. Private keys never pass through
founder code or Mallory. For default `n=5, t=3`:

```powershell
python -m treasury.server --init-identity
python -m treasury.member --name M1 --init-identity
python -m treasury.member --name M2 --init-identity
python -m treasury.member --name M3 --init-identity
python -m treasury.member --name M4 --init-identity
python -m treasury.member --name M5 --init-identity
python -m treasury.founder --n 5 --t 3
```

The owner keeps `runtime/data/<name>/identity.key`. Only public PEM keys, certificates
and `setup.json` go into `runtime/data/public/`. All programs use the trusted
`public/founder.pub`; this setup directory is the out-of-band trust distribution.
Certificates expire on **2026-12-31 (inclusive, UTC date)**. Founder refuses to overwrite
existing certificates/setup. Identity initialization reuses an existing owner key.
For a fresh evaluation run, pass the same new `--data-dir runtime/run2` to every setup
and running command. For `n=4,t=2`, initialize M1 through M4 and run founder with
`--n 4 --t 2`. Server reads these parameters from public setup.

## Secure communication

With the environment active in each terminal:

```powershell
# Terminal 1
python -m treasury.server
# Terminal 2
python -m treasury.member --name M1
# Terminal 3
python -m treasury.member --name M2
```

Expected logs: certificate verification OK, role-specific handshake signature OK,
session established on server, nonce 0/tag OK and channel probe acknowledged on member.
The probe only echoes a demonstration message; every treasury operation is rejected
until its real authentication/application handler is integrated. Normal logs omit
application payloads, private keys and session keys. Logs append to
`runtime/logs/<program>.log`; set `TREASURY_LOG_DIR` in all terminals to use a new folder.
Server supports concurrent member connections. `--once` serves one connection for demos/tests.

## A1: unsigned handshake comparison

Stop any previous server and start these in three terminals:

```powershell
python -m treasury.server --weak unsigned-handshake
python -m treasury.mallory --attack A1 --weak unsigned-handshake
python -m treasury.member --name M1 --port 6000 --weak unsigned-handshake --message "A1 confidentiality marker"
```

Mallory forwards the real certificates, substitutes fresh ephemeral points, derives
a different channel with each peer, and logs `A1 PLAINTEXT` containing the marker.
She does not read any identity files. This demonstrates confidentiality loss with
real ECDH/AES-GCM, not mocked crypto.

Restart all three without the weakness:

```powershell
python -m treasury.server
python -m treasury.mallory --attack A1
python -m treasury.member --name M1 --port 6000
```

Member rejects `hs-server signature verification FAILED`; Mallory logs `A1 BLOCKED`.
The check is `_verify()` in `treasury/channel.py`. No application data is sent.
Mallory handles one connection and exits; restart it for each demo.

**Pending Essam:** route real login and signed requests over `Session`. A1 will then
log those messages automatically. Add a controlled edit to a request body in
`proxy_connection()` while preserving its signature, and demonstrate rejection by
Essam's verifier. That assessed signed-request result has not yet been demonstrated.
Do not treat the channel probe as a login or a ledger entry.

## Plaintext, replay and tamper scenarios

Plaintext retains the signed handshake, then sends unencrypted application JSON:

```powershell
python -m treasury.server --weak no-encryption
python -m treasury.member --name M1 --weak no-encryption
```

Replay: restart a secure server, then run Mallory and a member:

```powershell
python -m treasury.server
python -m treasury.mallory --attack replay-frame
python -m treasury.member --name M1 --port 6000
```

The proxy transparently relays the authenticated handshake, then repeats the first
ciphertext frame. Server closes with `nonce validation FAILED: expected 1, got 0`.
The first valid probe can receive its acknowledgement before closure; the rejection
is established by the server log, not the member's exit code. For tag tampering,
restart the same programs with `--attack tamper-frame`; server logs
`AES-GCM authentication tag FAILED` and closes.

## Wireshark evidence (Essam)

Install Wireshark and Npcap loopback support on Windows. Select **Adapter for loopback
traffic capture** (Linux `lo`, macOS `lo0`). Start capture before running a scenario;
set display filter `tcp.port == 5050 || tcp.port == 6000`. Use Follow TCP Stream;
inspect raw/hex bytes for encrypted payloads. TCP segments are not application frames:
reassemble the stream, read the four-byte length, then the twelve-byte nonce.

| File | Commands/scenario above | Point at |
|---|---|---|
| `1_plain.pcapng` | no-encryption | Readable JSON after signed handshake |
| `2_secure.pcapng` | secure direct | Three JSON handshake messages, GROUP in certificates, X/Y; then nonce + ciphertext/tag |
| `3_A1_mitm.pcapng` | weak A1 | Two connections on ports 6000/5050; substituted X/Y; Mallory plaintext log |
| `4_A3_short_challenge.pcapng` | Only if A3 is selected | Not implemented/selected; assignment makes this conditional |
| `5_A4_replay.pcapng` | Only if A4 is selected | Not implemented/selected; assignment makes this conditional |
| `6_replayed_frame.pcapng` | replay-frame | Identical encrypted frame/nonce, then server closes |

Save each capture with every participating program's logs from the same run. Use a
fresh log directory per run (PowerShell: `$env:TREASURY_LOG_DIR='runtime/evidence/2_secure'`).
Also record A1 secure rejection and each required attack's four steps in <=3 minutes.
No packet captures or recordings were fabricated. Wireshark/tshark were not available
on PATH in the development environment. All captures/recordings require manual collection.
The full plain/secure/A1 runs must be repeated after Essam supplies login and requests.
The Overview says six captures, while Milestone 1 makes A3/A4 captures conditional;
with bonus A7 selected, confirm the final evidence set with the TA.

## Tests, CI and documents

```powershell
python -m unittest discover -s tests -v
```

Tests include real cryptography, an independent RFC5869 HKDF calculation, malformed
frames, certificate rejection, fresh keys, directional counters, and founder/server/
member/Mallory processes. The two starter tests remain. CI runs this command on PRs
and develop/John branch pushes, on Windows/Linux with Python 3.10/3.12.
See [test results](docs/TEST_RESULTS.md), [integration guide](docs/INTEGRATION.md),
[John's design sheet portion](docs/JOHN_DESIGN_SHEET.md),
[requirement map](docs/JOHN_REQUIREMENTS.md), and [implementation report](docs/IMPLEMENTATION_REPORT.md).
The four instructor PDFs are copied into `docs/` as local references and ignored by Git.

## Limitations and remaining work

- Essam must implement both login variants, registration, persistent signed-request
  sequence checks and ledger. Divan owns shares/vault/proofs/A5; Yassin owns voting/A7.
- Private files are separated by owner and created with restrictive POSIX modes.
  On Windows, configure owner directory ACLs if separate OS accounts are used.
  A shared OS account can read files; this educational layout is not OS isolation.
- Python/OpenSSL do not guarantee physical memory zeroization. Ephemeral keys are
  scoped to handshakes, never serialized/logged, and sessions drop directional keys
  on close. The trusted founder key/public setup must be provisioned out of band.
- No certificate revocation, production DoS controls, persistent authentication state
  or automatic renewal is included. After the specified expiry, fresh certificate
  policy requires an instructor-approved date change; integration tests will reject
  expired setup certificates too.
- Weak flags are local, explicit, never negotiated from untrusted messages, and off
  by default. A1 intentionally exposes plaintext only in Mallory's demonstration log.
- The linked repository was public at inspection; the official submission requires
  a private repository and TA invitation. Owner must arrange this before submission.
- Streamlit is deferred to `feature/john-streamlit-dashboard` after all milestones
  and attack demonstrations. It will call existing CLI/service interfaces, show real
  results/logs/evidence, and retain the original TCP paths and separate processes.
