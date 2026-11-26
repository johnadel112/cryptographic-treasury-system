# Official requirements mapped to John's implementation

Sources read in full before implementation: Overview (7 pages), Milestone 1 (3),
Milestone 2 (2), Milestone 3 (2), supplied on 26 November 2026. Their PDFs are local
`docs/Overview.pdf`, `Milestone_1.pdf`, `Milestone_2.pdf`, `Milestone_3.pdf` (Git-ignored).
The documents specify course requirements; execution authorization and team scope
come from John's request. No handout instruction expands this branch into teammates' work.

| Source | Requirement | Implementation / ownership |
|---|---|---|
| Overview pp1,3 | Extend starter, separate programs, TCP/JSON | Preserved modules, CLI programs and original tests; no HTTP/dashboard |
| Overview pp3?4 | GROUP, randomness, parameters, encoding | config/encoding/identity; RFC3526 p, subgroup g=4, secrets-based scalars |
| Overview p4; M1 item1 | Owner keys, founder certificates | identity/certificates/founder; owner setup first, founder public-key signing second |
| M1 item2 | Exact 3-message signed ECDH | channel.member_handshake/server_handshake; hs-server/hs-member signatures |
| M1 item3 | Exact HKDF and encrypted frames | channel/framing; no salt, prefix + raw transcript digest, directional AES-GCM |
| M1 items4?7 | Registration, logins, requests/ledger | Essam; unchanged TODO modules; callback and Session state documented |
| M1 A1 | MITM weak/secure comparison | mallory; real confidentiality failure on probe, secure rejection verified |
| M1 A1 | Login exposure and signed-request edit rejection | Pending Essam; no fabricated results |
| Overview pp4?5 | Terminal/file logs, public check values | logging_utils and per-program/channel events; no normal secret logging |
| M1 captures | Plain, secure, A1, encrypted replay | Reproducible CLI scenarios; actual capture collection remains Essam's |
| M2 | Threshold/vault and A5 | Divan; sharing/opening untouched; founder/server hooks documented |
| M3 | Private vote and bonus A7 | Yassin; voting untouched; generic secure message path available |
| Overview p6 | Design sheet <=4 pages, recordings | John portion allocated one page; final assembly and recordings still required |

Protocol decisions where the handout leaves representation details open:
ECDSA uses SHA256 and DER signatures as lowercase hex. Expiry is inclusive UTC date.
Encrypted application JSON is carried as raw nonce/ciphertext/tag inside the existing
length frame (per M1), while handshakes/plaintext demo frames remain JSON.
Public artifacts are distributed through a trusted local setup directory. No automatic
network trust bootstrap or implicit certificate acceptance is introduced.

Review differences from the supplied starter: no-encryption added to reserved flags;
role-specific signatures added while preserving build_handshake_transcript's hs label
for HKDF. The original baseline network helpers remain but secure CLIs bypass them.
Other students' assessed TODOs remain unimplemented. No Streamlit dependency/code exists.

The Overview asks for six captures but M1 explicitly conditions A3/A4 on choosing those
attacks. With A7 selected, clarify that evidence-count discrepancy with the TA.
The remote repository was public; submission requires private visibility and TA access.
