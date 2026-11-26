# Teammate integration guide

## Shared contracts

`config.py`: GROUP, P/Q/G, DEFAULT_N/T, `member_names(n)`, and
`valid_group_element(u)` (strict `1 < u < p`, subgroup check). `encoding.py`:
`canonical_json(value) -> bytes`, `sha256(bytes)`, `H(label, *values, q=Q)`.
Large integer wire values must be `format(value, "x")`; decode with `int(value,16)`
and validate bounds before arithmetic. No floats or nonfinite numbers in proofs.
Use `secrets.randbelow(Q)`/`secrets.randbits(...)`, never `random`.

`identity.py`: `initialize_identity(name, root)` runs only inside that owner's CLI;
`load_identity(name, root)` loads that owner's key, its public certificate and the
trusted founder public key. `Identity` provides `name`, `private_key`, `certificate`,
`founder_public_key`. Never load another identity's private directory. Founder reads
only its own private key and other programs' published PEM files.

`certificates.py`: `create_certificate(...)`, boolean `verify_certificate(...)`,
raising `check_certificate(...)` returning the certified P-256 public key;
`sign(key, value)` / `verify_signature(key, hex_signature, value)` sign canonical
JSON with ECDSA-SHA256 and DER signatures encoded as lowercase hex. These helpers
do not insert GROUP automatically: the caller must supply the exact prescribed
GROUP-bound transcript. They do not implement application authorization.

## Wire and channel

Handshake frames: four-byte unsigned big-endian length + UTF-8 JSON object.
Encrypted application frames: same length prefix + `nonce[12] || ciphertext || tag[16]`.
After decrypting, parse a JSON object. The binary wrapper is necessary to follow
Milestone 1's exact nonce-first encrypted frame layout. No extra JSON hex wrapper,
AAD or protocol labels are inserted. Plaintext demo uses length-prefixed JSON after
the same signed handshake. Signatures cover canonical JSON, regardless of wire whitespace.

`member_handshake(sock, identity, log, weak=None) -> Session` expects server identity
`server`. `server_handshake(sock, identity, allowed_members, log, weak=None) -> Session`
checks configured membership and requires the final member signature. Each handshake
uses fresh P-256 secrets and the exact role-specific transcripts. No downgrade negotiation.
Sockets must be IPv4 loopback and have a timeout; CLIs set ten seconds.

Use `with session:` followed by `session.send(dict)` and `session.receive()`.
Receive returns `None` for clean EOF; malformed input, nonce mismatch, tag failure or
I/O error closes the connection and raises. `ProtocolError` is the protocol exception;
certificate errors subclass it. Handshake failures close sockets before returning.
Do not catch an integrity error and continue on that session. Reconnect with fresh keys.
A Session supports one reader and one writer; serialize writes if sharing it.

`session.peer_name` and `peer_public_key` are certificate-bound transport identity
(only authenticated by the handshake in secure/no-encryption modes).
`session.authenticated` starts False. `session.state` is an empty per-connection dictionary
for future login state. Both are cleared on close. No dummy successful login exists.

## Essam: authentication and request integration (unfinished)

Keep `login.py` and `requests.py` as your implementation homes. Implement your assessed
protocols, retaining the starter names where practical. For example, the starter
interactive response signature lacks the commitment-state input; agree the needed
signature extension explicitly, rather than generating a new k after challenge receipt.
Use a per-session protocol state machine for registration, commitments/challenges,
responses and authenticated requests. Use separate persistent storage for the first
registered X_M, each member's last accepted seq and ledger. Last seq must survive
reconnects; do not store it only in `session.state`.

`server.serve_connection(..., handler=callback)` calls `callback(session, message)`
and sends its dictionary response. Connect your handler in server startup and replace
the member's probe with the real registration/login/request conversation. The current
`server.handle()` accepts only `channel-probe` and rejects every application operation.
A suggested dispatch convention is `type` for registration/login stages and `op` for
signed requests; these application type names are integration conventions, not extra
assignment-prescribed fields. Follow the official signed-request transcript exactly.

Set `session.authenticated=True` only after real Schnorr verification. Enforce identity,
login state, signature, and increasing seq before ledger/vault/voting changes. Guard
shared registration/sequence/ledger updates with a lock or transaction because server
connections run concurrently. Never expose x_M, signing keys or pending secrets in logs.

A1 already decrypts and relays arbitrary JSON. After integration, use it to show login
and requests in clear. At the marked Mallory extension point, alter a signed request
body while preserving its original signature. Record the real verifier rejecting it.
Until then this result is an outstanding dependency, not a passed demonstration.

## Divan: vault integration (unfinished)

Extend `founder.issue_certificates()` at its marked setup extension using validated
n/t and public identities. Do not regenerate or read member signing private keys.
Keep Shamir algorithms in `sharing.py`, proof creation/verification and combination
in `opening.py`. Deliver shares only to their owner's files, as prescribed; never
put shares or founder temporary secrets in `public/` or Git. Retain configurable n/t.

Route signed open requests, commitments, member contributions and proof verification
responses through Essam's authenticated handler using `Session.send/receive`. The
transport accepts arbitrary JSON object payloads, including lowercase hex proof values.
Suggested operations: `open-vault`, `decryption-contribution`, `proof-result`; agree
exact schemas with Essam. Verification response must reflect real proof checks;
no placeholders are accepted as valid. Divan implements A5 and real vault setup.

## Yassin: vote integration (unfinished)

Use `voting.py` and Essam's authenticated signed-request dispatcher for spending
requests, vote identifiers, encrypted ballots, acknowledgements and aggregate results.
The server owns fresh unique vote numbers and per-vote membership tracking. Store
these outside the channel. Follow the exact signed ballot transcript with GROUP,
member name and vote number. Use Divan's real threshold/proof integration for the total.
Suggested message types `vote-opened`, `ballot`, `vote-result` are conventions to agree.
Never put individual plaintext votes in logs or responses. A7's controlled ballot
transformation belongs at the Mallory relay extension point after voting exists;
secure channel protection must also be deliberately accounted for in that experiment.

## Logging, setup and future dashboard

`get_logger(program)` writes terminal plus `<program>.log`, with timestamp and identity.
Use `TREASURY_LOG_DIR` per evidence run. Log public quantities with first eight hex
digits next to a decision; do not log Session.state, private keys, x_M, vault keys or shares.
Founder logs certificate issuance; channel logs certificate/signature decisions,
connection events, counter/tag checks and rejections. A1 logs plaintext only intentionally.

The trusted public setup/founder key distribution is local and out of band. Normal
processes never read one another's private files; OS account/ACL separation is a
separate deployment concern. Fresh setup uses a fresh common --data-dir.

After all milestones and attack demonstrations, John can build the dashboard on
`feature/john-streamlit-dashboard`. Wrap real commands/results and route member actions
through existing TCP sessions. Show certificate/channel decisions, authentication,
vault approvals, votes, attack comparisons, saved captures and live logs. Keep secrets
out of UI state and preserve CLI execution. No dashboard code is part of this branch.
