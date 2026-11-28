"""Supervise one treasury server, one hub and five independent member UIs."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.request import urlopen
import webbrowser

BASE = Path(__file__).resolve().parents[1]
MEMBERS = tuple(f"M{i}" for i in range(1, 6))


def atomic_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.replace(temporary, path)


class Lab:
    def __init__(self, root, *, server_port=5050, hub_port=8500, member_base=8501):
        self.root = Path(root).resolve()
        self.data = self.root / "data"
        self.logs = self.root / "logs"
        self.control = self.root / "control"
        self.server_port, self.hub_port, self.member_base = server_port, hub_port, member_base
        self.processes = {}
        self.ready_pids = set()
        self.stopping = threading.Event()
        self.monitor = None
        self.lockfile = None
        ports = [server_port, hub_port, *range(member_base, member_base + 5)]
        if len(set(ports)) != 7 or any(not 1 <= p <= 65535 for p in ports):
            raise ValueError("Choose seven distinct ports in 1..65535")

    def acquire_lock(self):
        self.root.mkdir(parents=True, exist_ok=True)
        stream = (self.root / "launcher.lock").open("a+b")
        try:
            if stream.tell() == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            stream.close()
            raise ValueError("This runtime already has a running lab; open its hub instead") from exc
        self.lockfile = stream

    def setup(self):
        # Only public setup metadata is read by the supervisor. Owners initialize themselves.
        if self.data.exists():
            setup = self.data / "public" / "setup.json"
            if not setup.exists():
                raise ValueError("Incomplete runtime: choose a NEW --run-dir; existing files are preserved")
            public = json.loads(setup.read_text("utf-8"))
            if (public["n"], public["t"]) != (5, 3):
                raise ValueError("The five-member demonstration requires a 3-of-5 setup")
            return
        commands = [["server", "--init-identity"]]
        commands += [["member", "--name", name, "--init-identity"] for name in MEMBERS]
        commands += [["founder", "--n", "5", "--t", "3"]]
        with (self.logs / "setup.log").open("a", encoding="utf-8") as out:
            for module, *args in commands:
                subprocess.run([sys.executable, "-m", "treasury." + module, *args,
                                "--data-dir", str(self.data)], cwd=BASE, env=self.environment(),
                               stdout=out, stderr=subprocess.STDOUT, check=True, timeout=60)

    def environment(self, member=None):
        result = dict(os.environ, TREASURY_LOG_DIR=str(self.logs), TREASURY_LAB_ROOT=str(self.root),
                      TREASURY_LAB_HUB=f"http://127.0.0.1:{self.hub_port}",
                      TREASURY_DASHBOARD_DATA=str(self.data), TREASURY_DASHBOARD_PORT=str(self.server_port))
        if member:
            result.update(TREASURY_DASHBOARD_MEMBER=member, TREASURY_DASHBOARD_AUTOCONNECT="1")
        return result

    def launch(self, role):
        if role not in (*MEMBERS, "server", "hub"):
            raise ValueError("unknown lab role")
        current = self.processes.get(role)
        if current and current.poll() is None:
            return  # click/timer/duplicate requests cannot spawn duplicate owners
        if current:
            self.ready_pids.discard(current.pid)
        if role == "server":
            args = ["-m", "treasury.server", "--data-dir", str(self.data), "--port", str(self.server_port)]
        else:
            port = self.hub_port if role == "hub" else self.member_base + MEMBERS.index(role)
            script = "hub.py" if role == "hub" else "app.py"
            args = ["-m", "streamlit", "run", str(BASE / "dashboard" / script),
                    "--server.address", "127.0.0.1", "--server.port", str(port), "--server.headless", "true"]
        with (self.logs / (role + "-process.log")).open("a", encoding="utf-8") as out:
            self.processes[role] = subprocess.Popen([sys.executable, *args], cwd=BASE,
                env=self.environment(role if role in MEMBERS else None), stdin=subprocess.DEVNULL,
                stdout=out, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)

    def publish(self):
        members = []
        for name in MEMBERS:
            process = self.processes.get(name)
            port = self.member_base + MEMBERS.index(name)
            running = process is not None and process.poll() is None
            if running and process.pid not in self.ready_pids:
                try:
                    with urlopen(f"http://127.0.0.1:{port}/_stcore/health", timeout=.15) as response:
                        if response.status == 200:
                            self.ready_pids.add(process.pid)
                except OSError:
                    pass
            members.append({"name": name, "port": port, "running": running,
                            "ready": running and process.pid in self.ready_pids})
        server = self.processes.get("server")
        atomic_json(self.root / "lab.json", {
            "updated": datetime.now(timezone.utc).isoformat(), "hub_port": self.hub_port,
            "launcher_pid": os.getpid(),
            "server_port": self.server_port, "server_running": server is not None and server.poll() is None,
            "members": members, "threshold": 3, "runtime": str(self.root)})

    def start(self):
        # Never attach to an unrelated process that happens to occupy one of our ports.
        for port in [self.server_port, self.hub_port, *range(self.member_base, self.member_base + 5)]:
            with socket.socket() as sock:
                try:
                    sock.bind(("127.0.0.1", port))
                except OSError as exc:
                    raise ValueError(f"Port {port} is occupied. Stop the earlier demo or choose another port block.") from exc
        self.logs.mkdir(parents=True, exist_ok=True)
        self.control.mkdir(parents=True, exist_ok=True)
        try:
            self.acquire_lock()
            (self.control / "stop").unlink(missing_ok=True)
            self.setup()
            self.launch("server")
            # Wait for a real listener before member browsers can auto-authenticate.
            for _ in range(100):
                if self.processes["server"].poll() is not None:
                    raise RuntimeError("Treasury startup failed; inspect logs/server-process.log")
                try:
                    with socket.create_connection(("127.0.0.1", self.server_port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("Treasury startup timed out")
            for name in MEMBERS:
                self.launch(name)
            self.publish()
            self.launch("hub")
            for port in [self.hub_port, *range(self.member_base, self.member_base + 5)]:
                for _ in range(100):
                    try:
                        with urlopen(f"http://127.0.0.1:{port}/_stcore/health", timeout=.5) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise RuntimeError(f"Dashboard port {port} did not become ready; inspect logs")
            self.publish()
            self.monitor = threading.Thread(target=self.run_monitor, daemon=True)
            self.monitor.start()
        except BaseException:
            self.stop()
            raise

    def run_monitor(self):
        while not self.stopping.wait(.5):
            if (self.control / "stop").exists():
                (self.control / "stop").unlink()
                self.stopping.set()
                break
            for name in MEMBERS:
                request = self.control / ("launch-" + name)
                if request.exists():
                    try:
                        request.unlink()
                        self.launch(name)
                    except OSError:
                        pass  # next hub request can retry; no mutation is sent to treasury
            try:
                self.publish()
            except OSError:
                pass  # a reader may briefly hold the previous snapshot open on Windows

    def stop(self):
        self.stopping.set()
        if self.monitor:
            self.monitor.join(timeout=3)
        for process in reversed(list(self.processes.values())):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if self.lockfile:
            try:
                self.publish()
            finally:
                self.lockfile.close()
                self.lockfile = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, default=BASE / "runtime" / "lab")
    parser.add_argument("--server-port", type=int, default=5050)
    parser.add_argument("--hub-port", type=int, default=8500)
    parser.add_argument("--member-base-port", type=int, default=8501)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--stop", action="store_true", help="stop the lab owning this run directory")
    args = parser.parse_args()
    if args.stop:
        try:
            status = json.loads((args.run_dir / "lab.json").read_text("utf-8"))
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(status["updated"])).total_seconds()
            if age > 8 or not status["server_running"]:
                raise ValueError("This lab is not running")
            (args.run_dir / "control" / "stop").touch()
            print("Lab shutdown requested; runtime files are preserved.")
            return
        except (OSError, ValueError, KeyError) as exc:
            parser.exit(1, str(exc) + "\n")
    lab = Lab(args.run_dir, server_port=args.server_port, hub_port=args.hub_port, member_base=args.member_base_port)
    signal.signal(signal.SIGTERM, lambda *_: lab.stopping.set())
    try:
        lab.start()
        url = f"http://127.0.0.1:{args.hub_port}"
        print(f"Treasury demonstration ready: {url}\nAll five independent workspaces are running. Ctrl+C stops this lab; runtime files are preserved.", flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        while not lab.stopping.wait(1):
            if lab.processes["server"].poll() is not None:
                raise RuntimeError("Treasury server stopped; inspect logs, then restart the lab")
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(1, str(exc) + "\n")
    finally:
        lab.stop()


if __name__ == "__main__":
    main()
