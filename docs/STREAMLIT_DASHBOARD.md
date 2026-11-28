# Streamlit member dashboard

Branch: feature/john-streamlit-dashboard. Based on the complete integration branch (PR #6), not the older main implementation. This extension is now explicitly requested; the prior report/design sheet's "Streamlit deferred" statements describe the completed core phase and remain historical. Core protocols and CLI roles are retained.

## Run

For the complete five-member experience on Windows, use `start_demo.cmd`. The central hub on port 8500 launches/opens M1-M5 and the same server/runtime. See [multi-member evaluation guide](MULTI_MEMBER_DEMO.md). The individual launch commands below remain available.

1. Follow README's independent identity/founder setup using a fresh data directory. Founder and each owner remain separate CLI processes. Start `python -m treasury.server --data-dir runtime/live1` in its terminal.
2. Create `.venv-dashboard`, activate it, and install `python -m pip install -r requirements-dashboard.txt`.
3. Run `python -m treasury.dashboard --name M1 --data-dir runtime/live1 --port 8501`.
4. Open http://127.0.0.1:8501 and press Connect / refresh. Choose interactive or non-interactive Schnorr in the sidebar. Use separate dashboard processes on ports 8502..8505 for M2..M5; the browser cannot switch owner identity.
5. Stop each dashboard with Ctrl+C in its launch terminal; stop the treasury server separately. Never run two servers on one data root.

The default treasury endpoint is localhost:5050; `--treasury-port` supports an explicitly selected alternate local server. `--port` is the separate browser port. Dashboard binds to 127.0.0.1, with CORS/XSRF protections enabled and usage telemetry disabled. No cloud deployment is intended: anyone who can use this owner's local UI can act as this member, just as with its CLI. Use OS accounts/ACLs for actual ownership isolation.

Use a separate virtual environment for the PDF builder (`requirements-docs.txt`): ReportLab 5.1.2 requires Pillow >=13 while this pinned Streamlit release requires Pillow <13. Core CLI dependencies remain in requirements-lock.txt. Streamlit 1.58.0 retains Python 3.10 support; Starlette is pinned to 0.52.1 after live browser testing exposed a static-response incompatibility with Starlette 1.10.0. Playwright is only an optional local visual verification tool, not a dashboard runtime dependency.

## Screen workflow

| Screen | Real behavior |
|---|---|
| Overview | Authenticated snapshot of threshold, recent operations, participation and accepted-request count. No invented balance or security telemetry. |
| Vault | Signed opening request, progress to t unique valid contributions, own-share proof submission, and explicit retrieval/download after recovery. Duplicate contribution button disables after server acknowledgement. |
| Voting | Positive whole-unit amount/reason creates a signed spend. Each fixed owner encrypts one private ballot. All n ballots precede threshold tally; final aggregate yes/no chart and >=3 decision appear only after finalization. |
| Activity | Last 100 accepted request metadata records and browser-local structured success/rejection events. Proofs, signatures, plaintext ballot choices and shares are omitted. Events can be downloaded as JSON. |
| Evidence | Repository-recorded A1/A5/A7/A3/replay and secure/plain results, matching server logs, and available real packet captures. Clearly labelled recorded evidence, never claimed to be a live check. |

Live workspace fragments refresh authenticated snapshots every five seconds while the browser session is active. Pause this in the sidebar when desired. Spending forms sit outside the timed fragment, so drafts survive polling; ballot choices require an explicit submit button. Each refresh is itself an authenticated signed request and appears in the next ledger snapshot. The overview displays latest-100 operation counts, labels that window, and exposes full totals separately. Ballots remain encrypted; the form's local choice is never included in action-event exports. The treasury server is not given plaintext ballots.

To demonstrate vault opening: M1 requests opening, M1/M3/M5 open their own workspaces, refresh/select the same operation, then Contribute my share. Before three contributions it remains collecting; afterward Retrieve recovered file authenticates a new status request and offers a download. Repeat using a new opening ID and M2/M4/M5.

To demonstrate voting: M1 creates a spending request; five owners refresh and cast ballots; three owners contribute after collection closes. The chart is the actual aggregate. Approve iff yes >=3 even for other threshold configurations. Invalid signatures/proofs/duplicates remain server-enforced. No UI callback directly invokes TreasuryApplication or reads application.json.

## Failure handling and privacy

Missing owner setup, stopped server, certificate/handshake rejection and application rejections render as actionable errors. An interrupted action may already have been accepted; refresh before retrying. There is no automatic mutation retry. Fresh connections prevent stale TCP sessions and keys from being cached across reruns. Clear session removes snapshots, local events and downloaded bytes from browser session state; it does not erase the underlying owner keys or make this a password-protected multiuser service.

The signed overview endpoint has an explicit field allowlist. Its participation booleans refer only to the authenticated member; the contributors list contains the authenticated identities of accepted decryption contributions, not their proofs or shares. Recovered file bytes are excluded until an explicit authorized status call. Public evidence only reads fixed paths under captures/integrated; users cannot browse arbitrary server files through the UI. Historical capture hashes refer to the core integration source at collection time; the new overview endpoint does not retroactively alter that evidence.

The launcher fixes owner name/data root/server port in process environment. It exposes no weakness flags, arbitrary command runner, shell or member-key upload. Ballot validity and threshold-collusion limitations from the core report still apply.

## Verification

`python -m pytest -v` in the dashboard environment includes the core suite and tests/test_dashboard.py. Dashboard tests use real founder setup, actual cryptography and TCP service; AppTest drives real form buttons, a threshold opening, encrypted ballots, aggregate tally, missing setup, weakened-handshake rejection and session clearing. A private-file guard rejects attempted reads from another member's directory. The existing Windows/Ubuntu Python 3.10/3.12 CI matrix installs the optional dashboard requirements so UI tests cannot silently disappear there.

Framework references: [Streamlit AppTest](https://docs.streamlit.io/develop/api-reference/app-testing/st.testing.v1.apptest), [session state](https://docs.streamlit.io/develop/concepts/architecture/session-state), and [configuration](https://docs.streamlit.io/develop/api-reference/configuration/config.toml).

## Recorded validation on 27 November 2026

Clean dashboard environment: `pip check` reports no broken requirements. Full suite: **136 passed, 1 third-party pandas deprecation warning in 290.98s**. After pinning the live-server dependency and improving protocol-error messages, the focused dashboard suite passed **5 tests in 33.43s**. [JUnit evidence](evidence/dashboard-tests.xml) contains the full run. CI runs the same suite on Windows/Ubuntu and Python 3.10/3.12; consult the dashboard PR checks for remote results.

Headless Edge against the actual local Streamlit server verified connect, signed vault-opening and spending forms, no HTTP errors after the dependency fix, and desktop plus 390px mobile layouts. The mobile sidebar collapses and the page has no horizontal overflow. This [live voting screenshot](images/dashboard-voting.png) shows a real pending vote created during browser verification, not a mocked approval. The preview runtime is ignored by Git.
