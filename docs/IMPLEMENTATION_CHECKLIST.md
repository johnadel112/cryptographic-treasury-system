# Implementation checklist

## First session — everyone
- [ ] Set the same `GROUP` value in `treasury/config.py`.
- [ ] Create and activate a virtual environment; install requirements.
- [ ] Run the baseline server and member in two terminals.
- [ ] Confirm `runtime/logs/server.log` and `runtime/logs/M1.log` are created.
- [ ] Initialize a private GitHub repository and ensure every student commits their own work.

## Milestone 1 — secure channel and login
- [ ] Founder and program P-256 key generation and private-key storage.
- [ ] Founder-signed certificates; verify signature, group, expected name and expiry.
- [ ] Signed ephemeral ECDH handshake; reject invalid/missing signatures.
- [ ] HKDF-SHA256 directional keys and AES-256-GCM framing with monotonic counters.
- [ ] Login-secret registration and interactive proof-of-knowledge login.
- [ ] Signed requests with strictly increasing sequence numbers.
- [ ] Mandatory A1: implement `--weak unsigned-handshake`; demonstrate the MITM proxy and secure rejection.
- [ ] Optional: choose from A2, A3, A4. Non-interactive login is only needed for A4.

## Milestone 2 — treasury key
- [ ] General Shamir sharing for configurable `t` and `n`.
- [ ] Signed public commitments and member-side share verification.
- [ ] Encrypted vault file and erasure of founder's temporary secret values.
- [ ] Decryption shares with equality-of-discrete-logs proofs.
- [ ] Lagrange combination using any valid threshold-sized subset.
- [ ] Mandatory A5: implement `--weak no-proof`; show invalid share damage and proof-based rejection.
- [ ] Optional bonus A6: implement `--weak no-share-check`.

## Milestone 3 — private spending vote
- [ ] Signed spending request and unique vote number.
- [ ] Encrypted yes/no ballot and ballot signature.
- [ ] Aggregate ciphertext without exposing individual votes.
- [ ] Threshold decryption of the aggregate and recovery of total yes votes.
- [ ] Optional bonus A7: implement `--weak unsigned-ballots`.

## Evaluation and submission
- [ ] Write test cases for normal behavior, invalid inputs and replay attempts.
- [ ] For every test, record expected result, actual result, and a short explanation.
- [ ] Capture the Milestone 1 Wireshark traces listed in the handout.
- [ ] Keep the logs from each matching run with its capture.
- [ ] README contains exact run commands; design sheet is no more than four pages.
- [ ] Screen-record each required attack; keep each recording at or below three minutes.
