"""Optional real-browser verification of seven independent local processes.
Install playwright in the dashboard venv, then: python scripts/verify_lab_browser.py
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import shutil
import sys
import time

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from treasury.lab import Lab
from treasury.vault import VAULT_DEFAULT_CONTENT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--server-port", type=int, default=6050)
    parser.add_argument("--hub-port", type=int, default=8600)
    parser.add_argument("--member-base-port", type=int, default=8601)
    parser.add_argument("--browser", help="Optional installed Chromium/Edge executable")
    args = parser.parse_args()
    from playwright.sync_api import sync_playwright, expect
    root = args.run_dir or BASE / "runtime" / ("lab-browser-" + secrets.token_hex(5))
    if root.exists():
        parser.error("verification requires a new run directory")
    lab = Lab(root, server_port=args.server_port, hub_port=args.hub_port, member_base=args.member_base_port)
    executable = args.browser
    if not executable:
        for candidate in [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                          shutil.which("chromium"), shutil.which("google-chrome")]:
            if candidate and Path(candidate).exists():
                executable = candidate
                break
    try:
        lab.start()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, **({"executable_path": executable} if executable else {}))
            hub = browser.new_page(viewport={"width": 1440, "height": 1000})
            hub.goto(f"http://127.0.0.1:{lab.hub_port}", wait_until="networkidle")
            expect(hub.get_by_role("link", name="Open M5", exact=True)).to_be_visible()
            hub.screenshot(path=str(root / "hub.png"), full_page=True)
            pages = {}
            for i in range(1, 6):
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                page.goto(f"http://127.0.0.1:{lab.member_base+i-1}", wait_until="networkidle")
                page.get_by_text("Last verified snapshot:", exact=False).wait_for(timeout=30000)
                page.get_by_test_id("stSidebar").get_by_text("Vault", exact=True).click()
                pages[i] = page
            pages[1].get_by_role("button", name="Request vault opening").click()
            for page in pages.values():
                page.get_by_role("button", name="Contribute my share").wait_for(timeout=30000)
            for i in (1, 3):
                pages[i].get_by_role("button", name="Contribute my share").click()
                pages[i].get_by_text("Your contribution has been accepted.", exact=True).wait_for(timeout=30000)
            pages[2].get_by_text("Verified contributors: M1, M3", exact=True).wait_for(timeout=30000)
            assert pages[2].get_by_role("button", name="Retrieve recovered file").count() == 0
            pages[5].get_by_role("button", name="Contribute my share").click()
            for page in pages.values():
                page.get_by_role("button", name="Retrieve recovered file").wait_for(timeout=30000)
                page.get_by_text("Verified contributors: M1, M3, M5", exact=True).wait_for(timeout=30000)
            pages[1].get_by_role("button", name="Retrieve recovered file").click()
            with pages[1].expect_download() as downloaded:
                pages[1].get_by_role("button", name="Download recovered file", exact=True).click()
            assert Path(downloaded.value.path()).read_bytes() == VAULT_DEFAULT_CONTENT
            pages[1].screenshot(path=str(root / "opened-vault.png"), full_page=True)
            for page in pages.values():
                page.get_by_test_id("stSidebar").get_by_text("Voting", exact=True).click()
            # Draft spending input is outside timed fragments and must survive polling.
            pages[2].get_by_role("textbox", name="Reason", exact=True).fill("Unsubmitted draft stays local")
            pages[1].get_by_role("textbox", name="Reason", exact=True).fill("Five-workspace evaluation")
            pages[1].get_by_role("button", name="Create signed spending request").click()
            for page in pages.values():
                page.get_by_role("button", name="Encrypt and submit ballot").wait_for(timeout=30000)
            pages[1].get_by_text("Approve", exact=True).click()
            pages[1].wait_for_timeout(6000)
            expect(pages[1].get_by_role("radio", name="Approve", exact=True)).to_be_checked()
            expect(pages[2].get_by_role("textbox", name="Reason", exact=True)).to_have_value("Unsubmitted draft stays local")
            for i, page in pages.items():
                page.get_by_text("Approve" if i in (1, 3, 5) else "Reject", exact=True).click()
                page.get_by_role("button", name="Encrypt and submit ballot").click()
                if i < 5:
                    page.get_by_text("Your encrypted ballot has been accepted.", exact=False).wait_for(timeout=30000)
            for page in pages.values():
                page.get_by_role("button", name="Contribute my share").wait_for(timeout=30000)
            for i in (2, 4, 5):
                pages[i].get_by_role("button", name="Contribute my share").click()
                if i != 5:
                    pages[i].get_by_text("Your contribution has been accepted.", exact=True).wait_for(timeout=30000)
            for page in pages.values():
                page.get_by_text("Approved", exact=True).wait_for(timeout=30000)
                page.get_by_text("Verified contributors: M2, M4, M5", exact=True).wait_for(timeout=30000)
                yes = page.get_by_test_id("stMetric").filter(has=page.get_by_text("Yes", exact=True))
                expect(yes.get_by_test_id("stMetricValue")).to_have_text("3")
                assert page.get_by_test_id("stException").count() == 0
            pages[1].screenshot(path=str(root / "final-vote.png"), full_page=True)
            old = lab.processes["M4"]
            old.terminate(); old.wait(timeout=5)
            expect(hub.get_by_role("button", name="Launch M4", exact=True)).to_be_enabled(timeout=15000)
            hub.get_by_role("button", name="Launch M4", exact=True).click()
            deadline = time.monotonic() + 15
            while lab.processes["M4"].pid == old.pid and time.monotonic() < deadline:
                time.sleep(.1)
            assert lab.processes["M4"].pid != old.pid
            expect(hub.get_by_role("button", name="Launch M4", exact=True)).to_be_disabled(timeout=15000)
            # Verify it actually serves the owner again, not merely that a PID exists.
            for attempt in range(30):
                try:
                    pages[4].goto(f"http://127.0.0.1:{lab.member_base+3}", wait_until="networkidle")
                    break
                except Exception:
                    if attempt == 29: raise
                    time.sleep(.2)
            pages[4].get_by_text("Last verified snapshot:", exact=False).wait_for(timeout=30000)
            browser.close()
        result = {"created_utc": datetime.now(timezone.utc).isoformat(), "workspaces": 5,
                  "independent_processes": 7, "same_opening": True, "two_insufficient": True,
                  "vault_contributors": ["M1", "M3", "M5"], "recovered_bytes_match": True,
                  "automatic_refresh": True, "drafts_preserved": True, "yes_count": 3,
                  "approved": True, "tally_contributors": ["M2", "M4", "M5"], "hub_relaunch": True}
        (root / "browser-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps({"run_dir": str(root), **result}), flush=True)
    finally:
        lab.stop()


if __name__ == "__main__":
    main()
