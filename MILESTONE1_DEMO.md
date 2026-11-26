# Milestone 1 Demonstration Instructions (Student 2 – Essam)

## Overview
This branch (`feature/essam-authentication`) implements:
- **Milestone 1 Authentication & Signed Requests**:
  - Separate Schnorr login secret $x_M \in \mathbb{Z}_q$ per member and server-side public key $X_M = g^{x_M} \bmod p$ registration (`AuthRegistry` in `src/ledger.py`), preventing unauthorized registration replacement.
  - Interactive Schnorr zero-knowledge login with 128-bit challenge $e$ (`src/auth_server.py`, `src/auth_client.py`).
  - Non-interactive Schnorr zero-knowledge login with fresh 128-bit server nonce $N$ and single-use nonce validation.
  - ECDSA-signed requests (`["request", GROUP, name, seq, op, body]`) with strict monotonic sequence validation (`seq > last_seq`), replay/tampering rejection, persistent accepted-request ledger (`RequestLedger`), and authentication/request logging.
- **Milestones 2 & 3 Authentication Integration**:
  - Authenticated session helpers and server validation for vault-opening requests (`open_vault`), decryption contributions (`decrypt_share`), spending requests (`spend_request`), and ECDSA-signed ballots (`["ballot", GROUP, name, vote_number, c_1, c_2]`).
- **Wireshark Captures & Program Logs**:
  - Stored in `captures/` with matching execution logs in `captures/logs/`.

## Running the Authentication Tests
```powershell
python -m pytest -v
```

## Regenerating Wireshark Captures & Logs
Requires Wireshark (`tshark.exe` / Npcap loopback adapter):
```powershell
python scripts/run_captures.py
```

## Wireshark Inspection Guide
Open any capture in `captures/` with display filter:
```
tcp.port == 5050 || tcp.port == 6000
```

| Capture File | Logs Directory | What to Point At in Wireshark |
| --- | --- | --- |
| `captures/1_plain.pcapng` | `captures/logs/1_plain/` | Handshake followed by plaintext JSON frames showing login `R`, `z`, and `spend` request in clear (`--weak no-encryption`). |
| `captures/2_secure.pcapng` | `captures/logs/2_secure/` | Three handshake messages in clear (`GROUP` in certs, `X`, `Y`); all subsequent frames are AES-256-GCM ciphertext prefixed with 12-byte big-endian nonce counters `0, 1, 2, ...`. |
| `captures/3_A1_mitm.pcapng` | `captures/logs/3_A1_mitm/` | Two TCP connections (M1 -> `6000` and Mallory -> `5050`) under `--weak unsigned-handshake`; `X` sent by M1 differs from `X` received by server. Mallory logs login & request in clear, but her tampered request fails ECDSA verification on the server. |
| `captures/4_A3_short_challenge.pcapng` | `captures/logs/4_A3_short_challenge/` | One TCP connection per login attempt under `--weak short-challenge` (4-bit challenge); connection count matches `captures/logs/4_A3_short_challenge/mallory_a3.log`. |
| `captures/6_replayed_frame.pcapng` | `captures/logs/6_replayed_frame/` | Mallory resends captured encrypted frame `#6` (`nonce = 000000000000000000000003`) to port `5050`; server logs `Nonce counter mismatch` and closes the connection. |
