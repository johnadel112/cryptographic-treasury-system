# Design sheet ? John's portion (allocate one of four final pages)

GROUP: `16002216-16003727-16004417-16005162`. Team: John (infrastructure/channel/A1),
Essam (login/requests/ledger), Divan (vault/threshold/A5), Yassin (voting/A7).
The mapping of individual names to the four student IDs was not supplied; add it
before combining the final design sheet. Keep the complete team sheet <=4 rendered pages.

| Value | Chosen/created by; when | Who knows it | Classification |
|---|---|---|---|
| GROUP, p, q, g, n, t | Assignment/team; configuration/setup | Everyone | Public |
| Founder signing key | Founder; setup | Founder only | Secret, founder file |
| Owner signing key | Server or Mi; own initialization | That owner only | Secret, owner file |
| PEM public keys, certificates | Owners/founder; setup | Everyone | Public |
| x, y | Member/server; each connection | Respective peer only | Ephemeral secret |
| X=xP, Y=yP | Member/server; handshake | Network observers | Public |
| ECDH shared secret | Each endpoint; handshake | Endpoints | Secret, never stored/logged |
| m2s/s2m keys | Each endpoint; HKDF | Endpoints | Session secret, discarded on close |
| Directional nonce counters | Each endpoint; start at 0 | Visible on wire | Public, never repeat per key |
| Application plaintext | Application owner; each send | Endpoints (Mallory in weak A1) | Confidential as applicable |
| Ciphertext and GCM tag | Sending endpoint; each send | Network observers | Public, authenticated |

Certificate flow: each owner creates its P-256 key and publishes PEM. Founder signs
canonical `{group,name,public_key,expires}` with ECDSA-SHA256, appending hex DER `sig`.
Expiry is 2026-12-31 inclusive UTC. Each peer checks trusted founder signature, GROUP,
expected identity, expiry and P-256 key format. Founder never reads owner private keys.

Handshake (four-byte length + JSON; X/Y are uncompressed point hex):

1. M -> S: `{cert: cert_M, X}`.
2. S -> M: `{cert: cert_S, Y, sig: Sign_S(["hs-server",GROUP,name,X,Y])}`.
3. M -> S: `{sig: Sign_M(["hs-member",GROUP,name,X,Y])}`.

Signatures use canonical JSON. Failures close the connection. HKDF-SHA256, salt=None,
info=`UTF8("ICS505|"+GROUP+"|channel|") || SHA256(canonical(["hs",GROUP,name,X,Y]))`,
length=64; first 32 bytes m2s, last 32 s2m. Application frames are length +
`nonce[12] || AES-GCM ciphertext || tag[16]`, no AAD; independent 96-bit big-endian
counters start at zero. Reject any counter other than the next expected one or any
invalid tag. Login remains a separate, initially false state owned by Essam.

A1: Mallory wants plaintext; `--weak unsigned-handshake` omits both signatures,
allowing substituted X/Y and two channels. Secure mode rejects the substituted
server transcript. Signed application requests remain independently protected once
Essam implements them; demonstration pending. `no-encryption` is capture-only.

Memory limitation: Python cannot guarantee zeroization; ephemeral objects are scoped
to the handshake, never persisted, and session keys are dropped on close. Runtime
files are ignored by Git; OS ACLs provide actual cross-user file isolation.
