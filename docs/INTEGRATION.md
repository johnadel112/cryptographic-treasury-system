# Integrated backend contract

All production roles import `treasury`. The retired `src` package is a migration notice; original implementations remain in Git history. John supplied identity/channel infrastructure, Essam authentication/request arithmetic, Divan sharing/vault arithmetic, and Yassin voting arithmetic. Integration adds service orchestration and strict trust boundaries around those contributions.

## Owner-side client

`TreasuryMemberClient(name, data_dir=Path(...), port=5050)` is a context manager. Entering authenticates the channel, not the login. `login("interactive")` or `login("noninteractive")` registers the owner's public Schnorr key once if needed and authenticates the actual connection. `request(op, body)`, `ballot(vote_number, vote)`, and `contribute(operation_id)` return JSON-compatible results with `ok`, `result`, or `error`. The CLI maps failures to exit code 1. `contribute` loads only this owner's share, verifies it, and sends a signed complaint on invalid shares.

A future UI must execute in the member's owner context; it must not load every member key/share centrally. Do not call server handlers directly to bypass authentication. `info` is public setup/own registration metadata; `probe` is explicitly unauthenticated transport diagnostics.

## Service and state

`TreasuryApplication.handle(session, message)` uses `session.peer_name` from the verified certificate. Pending Schnorr challenges and authentication are connection-local. `StateStore.transaction()` serializes threads and atomically commits registration, request sequence, operation state and accepted ledger records. Validation failures roll back the entire candidate snapshot. Run one server per data directory; the lock does not coordinate multiple processes. State binds to the GROUP and signed setup digest and survives a server restart.

Signed request wire fields are exactly `seq`, `op`, `body`, `sig`. Signature transcript is `["request", GROUP, authenticated_name, seq, op, body]`. Operations: `ping`, `ledger`, `share-complaint`, `open-vault`, `spend`, `status`, `contribute`. A spend body has positive integer amount and nonempty reason. A contribution body binds `operation` and `proof` in the signed wrapper. Status body has `operation`. Rejected requests never advance sequence or become successful ledger operations.

Opening states: `collecting` -> `opened` or `failed`. Vote states: `voting` -> `collecting` (all n ballots) -> `finalized` or `failed`. Returned IDs identify all follow-up calls. Voting uses persisted increasing numbers and vault openings random IDs. `content_hex` appears only for an authorized recovered vault result; CLI omits it from display and optionally writes `--output`. Protect runtime state after opening.

## Trust and wire formats

One config/encoding implementation supplies GROUP, RFC group, canonical JSON and H. The entire public vault record including commitments, parameters and ciphertext is founder-signed. Verification keys are derived from these authenticated commitments, never accepted from a contributor. Proof fields: `member_index`, `d_i`, `T1`, `T2`, `z`. Challenge is exactly H("dec", i, c1, hi, di, T1, T2). Operation binding is in the outer signature; persistent exact-proof hashes reject reuse across operations without changing the prescribed challenge.

Ballots use `["ballot", GROUP, name, vote_number, c1, c2]` with canonical lower-case hex ciphertext. Only aggregate ciphertext is threshold-decrypted. All n authenticated members ballot once; at least t unique valid members decrypt. Approval is total >= 3, independently of t. No proof that each ciphertext encrypts a bit is claimed.

## Events and future presentation

Every role logs timestamp, identity, operation/check outcome and abbreviated public values to its own file and terminal. `TREASURY_LOG_DIR` chooses a run-specific directory. Results are structured JSON; logs remain diagnostic text rather than a versioned event-stream API. A future dashboard can render public operation results and accepted ledger entries, adding an event adapter if needed. No Streamlit code or dependency is included. Weak flags are local startup choices only; no network message can enable them.
