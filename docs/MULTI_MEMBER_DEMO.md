# Five-member live demonstration

## One Windows command

From the repository root: `start_demo.cmd` (PowerShell: `.\start_demo.cmd`). Python must be available on PATH; the first launch needs package download access. Later runs reuse the environment and `runtime/lab`. The script starts the treasury server, central Streamlit hub and all five fixed-owner workspaces. It opens http://127.0.0.1:8500 automatically.

| Role | Default address |
|---|---|
| Central demonstration hub | http://127.0.0.1:8500 |
| M1 | http://127.0.0.1:8501 |
| M2 | http://127.0.0.1:8502 |
| M3 | http://127.0.0.1:8503 |
| M4 | http://127.0.0.1:8504 |
| M5 | http://127.0.0.1:8505 |
| Treasury protocol | TCP 127.0.0.1:5050 |

The hub cards open separate browser tabs. Each tab connects to a DIFFERENT Streamlit process with a fixed member identity. All five processes share the same public setup and treasury server. The hub has no signing identity and cannot contribute or vote. Cards indicate process availability, not successful Schnorr login; each workspace verifies and authenticates independently.

## Vault demonstration: one operation, three owners

1. Open M1, M3 and M5 using the hub cards; each authenticates automatically.
2. In M1 choose Vault, then Request vault opening **once**. Note the complete operation ID in the selector.
3. In M3 and M5 choose Vault. The same opening appears within five seconds. Select the same ID if there are multiple operations. Do not request a new opening in each tab.
4. M1 and M3 each click Contribute my share. All tabs automatically show `Verified contributors: M1, M3` and 2/3; the file cannot yet be retrieved.
5. M5 contributes. Every open tab shows M1, M3, M5 and Opened. A verified duplicate contribution cannot count twice.
6. In any authenticated member workspace click Retrieve recovered file, then Download recovered file. This is the real decrypted file, not a success placeholder.
7. To show a different quorum, create a NEW opening and repeat with M2/M4/M5. Existing openings and owner keys are preserved.

## Private spending vote

1. M1 opens Voting and creates a signed spending request with amount and reason.
2. Open all five workspaces. Choose the same vote number. Cast three Approve and two Reject ballots using each owner's own tab. A selected choice is not submitted until Encrypt and submit ballot is clicked.
3. Workspaces update the received-ballot count automatically; no individual plaintext votes are displayed in the hub or treasury state.
4. After all five ballots, M2/M4/M5 each click Contribute my share for the aggregate. The screen names accepted contributors while withholding their secret shares.
5. All tabs show the actual final aggregate: 3 yes, 2 no, Approved. Repeat with two yes votes to show rejection. Approval needs three yes votes independently of cryptographic threshold.

## Restart, fresh runs and troubleshooting

- If a member process stops, its card changes to unavailable. Click Launch Mx, then Open Mx. The supervisor relaunches that same owner against the same runtime. Running members are not duplicated.
- Keep the startup terminal open. Ctrl+C stops the seven owned subprocesses and releases the runtime lock, preserving files and ledger. From another terminal, `.\start_demo.cmd --stop` also requests a clean shutdown (include the same --run-dir for a nondefault runtime). Rerun the command to resume.
- For a new evaluation: `.\start_demo.cmd --run-dir runtime/lab-rehearsal2`. Existing or incomplete setup is never silently overwritten. Use a fresh path after an interrupted first-time setup.
- If an earlier standalone preview occupies a port, stop it explicitly; the launcher will not kill unrelated processes. Alternate ports: `.\start_demo.cmd --server-port 6050 --hub-port 8600 --member-base-port 8601`.
- Two launchers cannot own one runtime even with different ports. The OS releases the launcher lock when its process exits; a forced kill can leave child processes, so use Ctrl+C normally and inspect process logs before restarting.
- Logs are under the chosen run directory's logs folder. No generated keys/shares or application state is tracked by Git. Launch markers and lab.json contain no cryptographic secrets.
- Automatic refresh may pause in a suspended/background browser tab; return to the tab or use Connect / refresh. Failed connections show an error; no mutation is automatically retried.
- The five-member hub deliberately uses the required 3-of-5 configuration. Other thresholds remain available through the core CLI/demos.

## Fifteen-minute flow

Spend two minutes on architecture and independent owner login, four on the shared vault and insufficient shares, four on private voting, three on the recorded A1/A5 controls under Evidence, and two on questions. Rehearse beforehand. The hub repeats the short vault/voting instructions next to the member cards so the presenter need not memorize ports.

## Verification commands

`python -m pytest -v` includes tests/test_lab.py and tests/test_dashboard.py: startup of seven processes, private-directory guard on supervisor/hub, runtime lock, occupied-port preservation, member relaunch and independent CLI contributions to the same opening. UI tests cover both login methods, real vault/vote flow and protocol rejection.

For real browser automation, install Playwright in the dashboard environment (`python -m pip install playwright==1.65.2`). On Windows the script uses installed Edge; elsewhere use `python -m playwright install chromium` or `--browser PATH`.

```sh
python scripts/verify_lab_browser.py
```

This launches its own fresh runtime/ports, opens all five actual workspaces, verifies auto-synchronized 2/3 then 3/3 recovery and downloaded bytes, casts five encrypted ballots, decrypts the aggregate through three different owner UIs, checks draft preservation and relaunches a stopped member through the hub. Results/screenshots/logs are recorded only after real execution; the seven test processes are stopped in finally. It does not read owner private files in the controller.

## Measured browser verification, 28 November 2026

The actual five-owner browser run verified a shared opening: M1/M3 alone remained collecting; M5 completed recovery; all five tabs automatically displayed M1/M3/M5 and the opened state; downloaded bytes matched the founder's original plaintext. It also cast five encrypted ballots, used M2/M4/M5 to decrypt the aggregate, observed 3 yes / Approved in every tab, preserved unsent spending/ballot drafts through timer updates, and relaunched M4 from the central card. [Measured result](evidence/multi-member-browser.json), [hub screenshot](images/multi-member-hub.png), [opened vault](images/multi-member-vault.png), [final vote](images/multi-member-vote.png).

The actual Windows start_demo.cmd was also executed with an alternate local port block; all seven processes started, and `python -m treasury.lab --stop` shut them down cleanly without removing runtime files. The supervisor/hub private-directory guard and relaunch tests passed (3 tests); the dashboard protocol/UI tests passed (5 tests). Full suite: **139 passed, 1 third-party pandas deprecation warning in 278.44s**; [JUnit evidence](evidence/multi-member-tests.xml).
