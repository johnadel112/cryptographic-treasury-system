# John's implementation report

Date: 26 November 2026. Working branch: `feature/john-secure-channel`.
The official starter is preserved in baseline commit `5f0867f`; code/tests/CI are in
`ec87f8c`. Main and develop initially point at that starter baseline. At initial verification, no merge into
main had been performed. John subsequently authorized publication and merging into main. Documentation is committed separately.

## Delivered

- Owner-generated P-256 signing keys, founder-issued five-field certificates,
  expiry 2026-12-31, validation of GROUP, identity, curve, key format and signature.
- Exact three-message authenticated ephemeral ECDH handshake, role-specific signatures,
  transcript-bound HKDF-SHA256 with no salt and directional AES-256-GCM keys.
- Existing four-byte TCP framing extended for encrypted binary frames. Strict independent
  zero-based counters, authenticated decryption, replay/tamper failure closes connections.
- Default-secure separate founder/server/member CLIs on loopback, configurable n/t,
  explicit no-encryption capture mode, local Mallory A1 plus replay/tag-tamper harnesses.
- Shared parameter/encoding/logging helpers, Session send/receive and initially false
  login state, application handler hook, documented vault and voting integration points.
- Test dependency lock, PR CI matrix, installation/run/evidence instructions, requirement
  map, per-test results and John's portion of the final design sheet.

## Files created

| Path | Purpose |
|---|---|
| `treasury/identity.py` | Owner-local key generation, public publication, identity loading |
| `tests/test_security.py` | Certificates, parameters, HKDF/GCM, framing, owner setup tests |
| `tests/test_processes.py` | Actual separate processes, TCP, A1, rejection/integration tests |
| `.github/workflows/tests.yml` | PR/push unittest CI on Windows/Linux, Python 3.10/3.12 |
| `requirements-lock.txt` | Exact tested dependency versions |
| `docs/INTEGRATION.md` | APIs, protocol framing, teammate ownership and dashboard deferral |
| `docs/JOHN_DESIGN_SHEET.md` | Compact certificate/channel flow and public/secret value table |
| `docs/JOHN_REQUIREMENTS.md` | Official document requirements mapped to implementation |
| `docs/TEST_RESULTS.md` | Expected/actual outcomes of all 60 executed tests |
| `docs/IMPLEMENTATION_REPORT.md` | This report |

Local-only additions: four instructor PDFs in docs, `.venv-john`, and verification
runtime keys/public artifacts/logs. These are ignored by Git and are not deliverable
private material. No handout PDFs are published to the public remote.

## Files modified

`.gitignore`, `README.md`, `requirements.txt`; `treasury/config.py`, `encoding.py`,
`logging_utils.py`, `framing.py`, `certificates.py`, `channel.py`, `founder.py`,
`server.py`, `member.py`, `mallory.py`.

Unchanged assessed modules: `login.py`, `requests.py`, `sharing.py`, `opening.py`,
`voting.py`. Original `network.py`, starter tests and checklist also remain intact.
No Streamlit implementation or dependency was introduced.

## Verification actually executed

- Original starter tests: 2 passed before implementation; original server/member
  baseline exchange succeeded with the configured GROUP.
- Final suite: **60 tests passed, 0 failures/errors/skips**, 9.888s on Windows Python
  3.12 with cryptography 50.0.2. Command: `python -m unittest discover -s tests -v`.
- Actual default n=5/t=3 setup with separate owner processes, founder signing,
  then independent M1 and M2 authenticated-handshake/encrypted-probe exchanges passed.
- Process tests verified certificate rejections, handshake signature failures,
  ciphertext replay/tag tampering, plaintext demonstration and both A1 modes.
- `git diff --check` passed; no differences in teammates' assessed modules.
- Git tracking audit found no runtime private keys, login secrets, session keys,
  shares or captures. Runtime tree and environment files are ignored.
- No Wireshark capture, attack recording, teammate protocol or dashboard result is claimed.

## Commands

From the project root, create/activate `.venv-john` and install
`python -m pip install -r requirements-lock.txt`. Run owner initialization for server
and M1 through M5, then `python -m treasury.founder --n 5 --t 3`.
Start `python -m treasury.server` and `python -m treasury.member --name M1` in separate
terminals. Full copyable setup and weak/secure/replay commands are in README.

Weak A1: add `--weak unsigned-handshake` to server/member, start
`python -m treasury.mallory --attack A1 --weak unsigned-handshake`, and send the member
to `--port 6000`. Secure comparison removes the weak flag from all three. Replay and
tamper use `--attack replay-frame` / `--attack tamper-frame` with secure peers.

## Integration, unfinished features and dependencies

| Owner | Next implementation |
|---|---|
| Essam | registration, interactive/noninteractive Schnorr login, signed requests, persistent sequence checks/ledger; plug into Session/serve_connection callback |
| Divan | founder share/vault setup, threshold contributions/proofs, signed open requests and A5 using the channel |
| Yassin | spending vote lifecycle, encrypted signed ballots, aggregation/threshold total and A7 |
| John (future phase) | final integration, complete A1 login/request evidence after Essam, then Streamlit on its separate branch |

A1 demonstrates real probe confidentiality loss today. Its assessed login visibility
and signed-request alteration/rejection remain pending Essam's real implementation.
No fake successful authentication or fabricated ledger entries are present.

## Security limits and manual evidence

Python does not guarantee memory zeroization. Ephemeral keys are scoped to handshakes,
not saved/logged; session key references are dropped on close. File layout isolates
program ownership by convention; POSIX modes/Windows ACLs and OS accounts determine
actual filesystem access. Founder public key/setup are trusted out-of-band inputs.
No revocation, production DoS defenses or automatic expiry renewal is provided.

Wireshark/tshark were not available on PATH. Essam must collect the plain, secure,
A1 and replay traces and matching logs; repeat full login/request scenarios after
integration. Record each required attack's weak/secure demonstration (<=3 minutes).
Confirm the Overview/M1 conditional-capture discrepancy with the TA for bonus A7.
Add each student's name-to-ID mapping and keep the final combined design sheet <=4 pages.
The repository was public at inspection; arrange private submission visibility and TA access.

## Recommended next steps

John has authorized publishing this feature and merging into main after CI. Essam should integrate
login/requests first so Divan and Yassin can use authenticated sessions. Then verify all
milestone live demos and signed-request protection under A1, collect evidence, assemble
the <=4-page design sheet, and only then start the dashboard branch.

## Publication status

Local commits are complete and the working tree was clean after verification.
An attempted atomic push of main/develop starter baselines plus the feature branch
was rejected by automatic approval review before execution. The stated reason was
publication of potentially nonpublic assignment/project implementation and documentation
to a public repository without explicit confirmation of public exposure, together with
updates to three branches. No push occurred and no PR was opened. Instructor PDFs and
runtime secrets were excluded from the proposed push. John subsequently explicitly approved publishing these commits to the linked repository
and merging into main. Publication can now proceed under that authorization. The original
rejection above records the earlier attempt, not a current approval blocker.
