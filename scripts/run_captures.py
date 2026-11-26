"""Automated Wireshark capture & log generator for Milestone 1 deliverables."""

import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.auth_client import TreasuryMemberClient
from src.auth_server import TreasuryAuthServer
from src.config import GROUP, PROXY_PORT, SERVER_HOST, SERVER_PORT
from src.keys import setup_pki
from src.proxy_mallory import FrameReplayProxy, MalloryMitmProxy, run_attack_a3

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
DUMPCAP = r"C:\Program Files\Wireshark\dumpcap.exe"
CAPTURES_DIR = BASE_DIR / "captures"
CAPTURE_FILTER = f"tcp port {SERVER_PORT} or tcp port {PROXY_PORT}"


def start_capture(pcap_path: Path) -> subprocess.Popen:
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    if pcap_path.exists():
        pcap_path.unlink()
    proc = subprocess.Popen(
        [
            TSHARK,
            "-i",
            r"\Device\NPF_Loopback",
            "-f",
            CAPTURE_FILTER,
            "-a",
            "duration:4",
            "-w",
            str(pcap_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stderr is not None
    deadline = time.time() + 10.0
    while time.time() < deadline:
        line = proc.stderr.readline()
        if "Capturing on" in line:
            break
    time.sleep(0.2)
    return proc


def stop_capture(proc: subprocess.Popen) -> None:
    proc.wait(timeout=15)


def reset_data(work_dir: Path) -> None:
    if work_dir.exists():
        shutil.rmtree(work_dir)
    setup_pki(work_dir, members=("M1", "M2", "M3", "M4", "M5"), group=GROUP)


def scenario_1_plain() -> None:
    work = BASE_DIR / "data_cap" / "1_plain"
    logs = CAPTURES_DIR / "logs" / "1_plain"
    reset_data(work)
    cap = start_capture(CAPTURES_DIR / "1_plain.pcapng")
    srv = TreasuryAuthServer(
        host=SERVER_HOST,
        port=SERVER_PORT,
        data_dir=work,
        log_file=logs / "server.log",
        weak_no_encryption=True,
    )
    srv.start()
    try:
        c1 = TreasuryMemberClient(
            "M1",
            host=SERVER_HOST,
            port=SERVER_PORT,
            data_dir=work,
            log_file=logs / "M1.log",
            weak_no_encryption=True,
        )
        c1.connect()
        c1.register()
        c1.login_interactive()
        c1.send_request("spend", {"amount": 50, "reason": "pizza"})
        c1.close()
    finally:
        srv.stop()
        stop_capture(cap)


def scenario_2_secure() -> None:
    work = BASE_DIR / "data_cap" / "2_secure"
    logs = CAPTURES_DIR / "logs" / "2_secure"
    reset_data(work)
    cap = start_capture(CAPTURES_DIR / "2_secure.pcapng")
    srv = TreasuryAuthServer(
        host=SERVER_HOST,
        port=SERVER_PORT,
        data_dir=work,
        log_file=logs / "server.log",
    )
    srv.start()
    try:
        c1 = TreasuryMemberClient(
            "M1",
            host=SERVER_HOST,
            port=SERVER_PORT,
            data_dir=work,
            log_file=logs / "M1.log",
        )
        c1.connect()
        c1.register()
        c1.login_interactive()
        c1.send_request("spend", {"amount": 50, "reason": "pizza"})
        c1.close()
    finally:
        srv.stop()
        stop_capture(cap)


def scenario_3_a1_mitm() -> None:
    work = BASE_DIR / "data_cap" / "3_A1_mitm"
    logs = CAPTURES_DIR / "logs" / "3_A1_mitm"
    reset_data(work)
    cap = start_capture(CAPTURES_DIR / "3_A1_mitm.pcapng")
    srv = TreasuryAuthServer(
        host=SERVER_HOST,
        port=SERVER_PORT,
        data_dir=work,
        log_file=logs / "server.log",
        weak_unsigned_handshake=True,
    )
    srv.start()
    proxy = MalloryMitmProxy(
        listen_host=SERVER_HOST,
        listen_port=PROXY_PORT,
        target_host=SERVER_HOST,
        target_port=SERVER_PORT,
        log_file=logs / "mallory_a1.log",
        tamper_first_request=True,
    )
    proxy.start()
    try:
        c1 = TreasuryMemberClient(
            "M1",
            host=SERVER_HOST,
            port=PROXY_PORT,
            data_dir=work,
            log_file=logs / "M1.log",
            weak_unsigned_handshake=True,
        )
        c1.connect()
        c1.register()
        c1.login_interactive()
        c1.send_request("spend", {"amount": 50, "reason": "pizza"})
        c1.close()
    finally:
        proxy.stop()
        srv.stop()
        stop_capture(cap)


def scenario_4_a3_short_challenge() -> None:
    work = BASE_DIR / "data_cap" / "4_A3_short_challenge"
    logs = CAPTURES_DIR / "logs" / "4_A3_short_challenge"
    reset_data(work)
    srv = TreasuryAuthServer(
        host=SERVER_HOST,
        port=SERVER_PORT,
        data_dir=work,
        log_file=logs / "server.log",
        weak_short_challenge=True,
    )
    srv.start()
    try:
        # Register M3 before starting the attack capture
        c3 = TreasuryMemberClient(
            "M3",
            host=SERVER_HOST,
            port=SERVER_PORT,
            data_dir=work,
            log_file=logs / "M3_register.log",
        )
        c3.connect()
        c3.register()
        c3.close()

        cap = start_capture(CAPTURES_DIR / "4_A3_short_challenge.pcapng")
        try:
            run_attack_a3(
                "M3",
                host=SERVER_HOST,
                port=SERVER_PORT,
                data_dir=work,
                max_attempts=128,
                log_file=logs / "mallory_a3.log",
            )
        finally:
            stop_capture(cap)
    finally:
        srv.stop()


def scenario_6_replayed_frame() -> None:
    work = BASE_DIR / "data_cap" / "6_replayed_frame"
    logs = CAPTURES_DIR / "logs" / "6_replayed_frame"
    reset_data(work)
    cap = start_capture(CAPTURES_DIR / "6_replayed_frame.pcapng")
    srv = TreasuryAuthServer(
        host=SERVER_HOST,
        port=SERVER_PORT,
        data_dir=work,
        log_file=logs / "server.log",
    )
    srv.start()
    proxy = FrameReplayProxy(
        listen_host=SERVER_HOST,
        listen_port=PROXY_PORT,
        target_host=SERVER_HOST,
        target_port=SERVER_PORT,
        replay_after_packets=6,
        log_file=logs / "mallory_replay.log",
    )
    proxy.start()
    try:
        c1 = TreasuryMemberClient(
            "M1",
            host=SERVER_HOST,
            port=PROXY_PORT,
            data_dir=work,
            log_file=logs / "M1.log",
        )
        c1.connect()
        c1.register()
        c1.login_interactive()
        c1.send_request("spend", {"amount": 50, "reason": "pizza"})
        time.sleep(0.3)
        c1.close()
    finally:
        proxy.stop()
        srv.stop()
        stop_capture(cap)


def main() -> None:
    scenario_1_plain()
    scenario_2_secure()
    scenario_3_a1_mitm()
    scenario_4_a3_short_challenge()
    scenario_6_replayed_frame()

    # Verify packet counts with tshark
    for name in (
        "1_plain.pcapng",
        "2_secure.pcapng",
        "3_A1_mitm.pcapng",
        "4_A3_short_challenge.pcapng",
        "6_replayed_frame.pcapng",
    ):
        pcap = CAPTURES_DIR / name
        res = subprocess.run(
            [TSHARK, "-r", str(pcap), "-Y", "tcp.port == 5050 || tcp.port == 6000"],
            capture_output=True,
            text=True,
            check=False,
        )
        lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
        print(f"{name}: {len(lines)} packets")

    # Clean temporary capture data_cap dir
    data_cap = BASE_DIR / "data_cap"
    if data_cap.exists():
        shutil.rmtree(data_cap)


if __name__ == "__main__":
    main()
