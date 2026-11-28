"""Supervisor never acts as a member; contributions come from independent CLIs."""
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import pytest
from treasury.lab import Lab, MEMBERS, BASE


def free_ports():
    for _ in range(100):
        base = 15000 + secrets.randbelow(30000)
        holders = []
        try:
            for port in range(base, base + 7):
                sock = socket.socket()
                holders.append(sock)
                sock.bind(("127.0.0.1", port))
            return base
        except OSError:
            pass
        finally:
            for sock in holders: sock.close()
    raise RuntimeError("no free lab port block")


def test_runtime_lock_prevents_two_supervisors(tmp_path):
    first, second = Lab(tmp_path), Lab(tmp_path)
    first.acquire_lock()
    try:
        with pytest.raises(ValueError, match="already has"):
            second.acquire_lock()
    finally:
        first.stop()
    second.acquire_lock()
    second.stop()


def test_occupied_port_preserves_existing_status(tmp_path):
    status = tmp_path / "lab.json"
    status.write_text('{"preserve":true}')
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        lab = Lab(tmp_path, server_port=sock.getsockname()[1])
        with pytest.raises(ValueError, match="occupied"):
            lab.start()
        lab.stop()
    assert json.loads(status.read_text()) == {"preserve": True}


def test_seven_process_lab_and_hub_relaunch(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest
    base = free_ports()
    lab = Lab(tmp_path, server_port=base, hub_port=base+1, member_base=base+2)
    original = Path.open
    def guarded(path, *args, **kwargs):
        for name in (*MEMBERS, "server", "founder"):
            if path.resolve().is_relative_to((lab.data / name).resolve()):
                raise AssertionError("supervisor/hub read a private owner directory")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", guarded)
    try:
        lab.start()
        assert len({p.pid for p in lab.processes.values()}) == 7
        monkeypatch.setenv("TREASURY_LAB_ROOT", str(tmp_path))
        at = AppTest.from_file(str(BASE / "dashboard" / "hub.py"), default_timeout=30).run()
        assert not at.exception
        assert {h.value for h in at.subheader if h.value in MEMBERS} == set(MEMBERS)
        old = lab.processes["M4"]
        old.terminate(); old.wait(timeout=5)
        lab.publish()
        at.run()
        next(b for b in at.button if b.label == "Launch M4").click().run()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and lab.processes["M4"].pid == old.pid:
            time.sleep(.1)
        assert lab.processes["M4"].pid != old.pid
        def member(name, *args):
            result = subprocess.run([sys.executable, "-m", "treasury.member", "--name", name,
                "--data-dir", str(lab.data), "--port", str(base), *args], cwd=BASE,
                capture_output=True, text=True, timeout=30, check=True)
            return json.loads(result.stdout)["result"]
        opening = member("M1", "--command", "open-vault")["id"]
        for name in ("M1", "M3"):
            assert member(name, "--command", "contribute", "--operation", opening)["state"] == "collecting"
        assert member("M5", "--command", "contribute", "--operation", opening)["state"] == "opened"
        snapshot = member("M2", "--command", "request", "--op", "overview")
        assert snapshot["operations"][0]["contributors"] == ["M1", "M3", "M5"]
    finally:
        lab.stop()
    assert all(p.poll() is not None for p in lab.processes.values())
