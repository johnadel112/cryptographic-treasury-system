# Cryptographic Treasury System - Combined Design Sheet
GIU ICS505 | 27 November 2026 | Page 1: configuration and ownership

GROUP: 16002216-16003727-16004417-16005162. Team: John, Essam, Divan, Yassin. Student IDs: 16002216, 16003727, 16004417, 16005162. INDIVIDUAL NAME-ID MAPPINGS UNCONFIRMED: team must complete before submission; order does not imply mapping.

Shared parameters: RFC 3526 Group 14 prime p, q=(p-1)/2, g=4. Default (t,n)=(3,5), configurable per fresh setup. P-256 identities; SHA-256; canonical sorted compact JSON; H hashes [ICS505,GROUP,label,...] with integer arguments in lowercase hex. TCP 127.0.0.1:5050; controlled Mallory :6000. One treasury package, independent owner processes.

| Value | Generator / time | Who knows / secrecy |
|---|---|---|
| Founder signing key; public key | Founder / initial identity | Founder private; public trust anchor |
| Owner P-256 key; certificate | Server or Mi / identity; founder / setup | Owner private key only; cert/public key public |
| Schnorr x_i, X_i=g^x_i | Mi / owner initialization, registration | x_i owner secret; X_i registered public |
| ECDH a,b; A,B; shared Z | Each endpoint / every connection | a,b owner-ephemeral; A,B public; Z endpoints |
| Directional K, counters | Endpoints / handshake, each record | K secret to endpoints; counters not secrets |
| Schnorr k,R; e or N; z | Mi per proof; server per attempt | k secret/ephemeral; R,e,N,z proof transcript |
| Treasury s, coefficients a_j | Founder / fresh setup | Founder setup-only secret; never persisted |
| Shares s_i=f(i) | Founder / setup | Mi alone after private distribution |
| C_j=g^a_j, h=C_0, h_i | Founder / setup; derived from C | Public; founder signs entire public record |
| Encapsulated m; r; file K | Founder / file encryption | Setup-only secrets; m/K recoverable at threshold |
| c1,c2,salt,nonce,ciphertext | Founder / vault encryption | Public signed record, ciphertext not plaintext |

No physical zeroization guarantee for Python objects. Local files require OS access controls. Server never opens member private files. Founder distribution is the sole setup exception; no production bulk-share opener exists.

---PAGE---
# Milestone 1 - authenticated channel, login and requests
Page 2: message flow and binding

1. Each owner initializes its own P-256 key; founder signs certificates binding name, GROUP, public key and expiry. Both endpoints verify founder, expected name, GROUP and validity before trusting identity.
2. Member and server exchange fresh ECDH points and role-labelled ECDSA signatures over both points and member identity. HKDF derives independent directional AES-256-GCM keys bound to this GROUP/session. The connection carries four-byte-length frames.
3. Each direction uses a monotonic 12-byte nonce counter and rejects unexpected counters or invalid tags. Public handshake metadata is visible; application frames are encrypted. Fresh ephemeral keys supply forward secrecy subject to endpoint secret handling.
4. Over that channel, Mi registers X_i once, bound to the verified member identity. Interactive login sends R=g^k; server returns fresh 128-bit e; Mi returns z=k+e*x_i mod q; server checks g^z=R*X_i^e.
5. Alternatively server issues fresh N, then Mi sends R,z with e=H(login,name,X_i,R,N). Pending challenge/nonce is connection-bound and consumed even on failure. Authentication never follows merely from a handshake or probe.
6. Authenticated Mi signs [request,GROUP,name,seq,op,body]. Server checks signature and increasing sequence and validates operation. State change, sequence and accepted-request ledger commit together under a thread lock and atomic snapshot replacement; failures roll back.

| Value | Generator / time | Who knows / secrecy |
|---|---|---|
| Request seq,op,body,sig | Member / each request | Endpoints over channel; accepted ledger retained |
| Registration and last_seq | Server / accepted transaction | Server persistent state; owner's public info |
| Session auth and challenge | Server / connection and attempt | Connection-local; never inferred from peer payload name |

Useful entry points: certificates.check_certificate; channel.member_handshake/server_handshake/SecureChannel; login.make_commitment/make_interactive_response/make_noninteractive_response; requests.verify_request; application.TreasuryApplication; ledger.StateStore.

Checks: wrong founder/GROUP/name/expiry, modified handshake/request/frame, request/frame replay, independent keys, nonce single-use, invalid subgroup, unauthorized operations, concurrent duplicate requests and state restart. Tests: test_security.py, test_processes.py, test_authentication.py and subprocess secure scenario.

---PAGE---
# Milestone 2 - verifiable threshold vault
Page 3: setup, opening and proof ownership

1. Founder samples degree t-1 f with f(0)=s, distributes s_i=f(i) privately and publishes C_j=g^a_j. It signs the whole public vault record. Each Mi verifies founder signature and g^s_i=product(C_j^(i^j)); invalid share produces a signed complaint and refusal.
2. Vault key h=g^s. Founder samples random subgroup m and fresh r, stores ElGamal (c1,c2)=(g^r,m*h^r). HKDF(m,salt,GROUP-bound info) produces AES-GCM file key. Only ciphertext/public record and distributed shares persist, not s, coefficients, r, m or file key.
3. An authenticated signed open-vault request creates a fresh operation ID. Public operation/ciphertext is available to authenticated participants. Each owner reads ONLY its own share.
4. Mi computes d_i=c1^s_i and fresh proof witness w: T1=g^w, T2=c1^w; e=H(dec,i,c1,h_i,d_i,T1,T2); z=w+e*s_i mod q. The signed request binds operation ID and full proof.
5. Server derives h_i from authenticated C_j; it does not trust contributor-supplied verification keys. Verify canonical integers, subgroup/scalar ranges, identity/index, g^z=T1*h_i^e AND c1^z=T2*d_i^e. Reject duplicate members, unknown identities and replayed proofs across operations.
6. At t unique valid shares, compute D=product(d_i^lambda_i), where lambda_i=product(j/(j-i)) modulo q over selected indices. Recover m=c2/D, derive file key and authenticate/decrypt file. Never reconstruct scalar s. Fewer than t remains collecting.

| Value | Generator / time | Who knows / secrecy |
|---|---|---|
| Operation ID and c1,c2 | Server / opening | Authenticated participants; public cryptographic input |
| Proof w | Mi / each contribution | Owner-only ephemeral secret |
| d_i,T1,T2,z,lambda_i | Mi / proof; server / combination | Public proof data (sent encrypted); no scalar share |
| D, recovered m and file key | Server / valid threshold reached | Server transient decryption material; not logged |
| Recovered file | Server / authenticated opening | Authorized result; persistent runtime state protected |

Tests verify M1/M3/M5 and M2/M4/M5 identical recovery, two-share insufficiency, 2-of-4, 4-of-5, invalid commitments/share/proof, cross-operation replay and server private-file access guard. Code: sharing.py, opening.py, vault.py, client.contribute, application._operation. Production vault_cli bulk opening is retired.

---PAGE---
# Milestone 3, attacks and limitations
Page 4: private spending and evaluation controls

1. Authenticated signed spend(amount,reason) creates a persisted unique vote number. Each of n authenticated members encrypts v in {0,1} with fresh r: (c1,c2)=(g^r,h^r*g^v), using the actual vault public key h.
2. Mi signs [ballot,GROUP,name,vote_number,c1,c2]. Server checks identity/signature/canonical subgroup elements/active vote and accepts one ciphertext per member. Individual plaintext v is never sent to or recorded by the server.
3. After all n ballots, multiply ciphertext components modulo p. The same threshold contribution protocol decrypts ONLY the aggregate. At least t unique valid proofs are required. Recover j by checking g^j for j=0..n; reject no-match results. Approve iff j>=3, independently of threshold t.

| Value | Generator / time | Who knows / secrecy |
|---|---|---|
| Vote number, amount, reason | Server / signed spend | Public operation metadata to authenticated clients |
| v and fresh r | Mi / ballot | Owner secret; not in server logs |
| Ballot c1,c2,signature | Mi / ballot | Server ciphertext; signed member/vote binding |
| Aggregate and final j | Server / n ballots then t proofs | Aggregate ciphertext; only final count disclosed |

| Attack | Weak goal / actual failure | Enabled control |
|---|---|---|
| A1 mandatory | Unsigned DH lets local Mallory read login | Handshake ECDSA rejects substitution; request ECDSA protects op even in weak channel |
| A5 mandatory | Same M3 d_i*g without proof checks causes file-tag failure | Both proof equations reject M3; valid M4 substitutes and recovery succeeds |
| A7 bonus | Unsigned ballot c2*g changes total 2 to 3 | Ballot signature rejects mutation; corrected tally 2. Same deliberately unsigned DH carrier in both comparisons |
| A3 preserved | Guessed 4-bit Schnorr challenge can pass | Fresh 128-bit challenge; signing identity alone is insufficient |
| Replay evidence | Repeat an encrypted record | Exact directional nonce counter closes connection |

Limitations: signature is not proof of v in {0,1}; malicious encrypted values require a suitable zero-knowledge bit-validity proof. Bounded totals catch only some bad ballots. All-n collection can stall; t-member collusion defeats threshold privacy. Trusted founder/filesystem, one server per state root, no production DoS guarantee, no physical Python zeroization. Weak switches are local CLI only and off by default. No Streamlit.

Evidence: 131 local pytest cases including 9 real-process scenarios; captures/integrated holds matching real captures/logs. Team still must confirm ID mappings, administrative access, <=3-minute attack recordings and 15-minute rehearsal. This sheet is generated as exactly four pages; source: docs/DESIGN_SHEET.md.
