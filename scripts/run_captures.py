"""Capture the integrated CLI application; preserve all existing evidence.

Example: python scripts/run_captures.py --scenario secure --interface 10
Requires tshark/Npcap. Data stays in ignored runtime; only matching logs/capture
and measured validation results go into the selected new evidence directory.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import queue
import secrets
import shutil
import subprocess
import sys
import threading
import time

BASE = Path(__file__).resolve().parents[1]
NAMES = {"plain":"1_plain", "secure":"2_secure", "A1":"3_A1_mitm", "A3":"4_A3_short_challenge", "replay":"6_replayed_frame"}
FILTER = "tcp.port == 5050 || tcp.port == 6000"


def inspect_capture(tshark, capture, scenario):
    result = subprocess.run([tshark,"-r",str(capture),"-Y",FILTER+" && tcp.len > 0 && !tcp.analysis.retransmission",
        "-T","fields","-e","tcp.stream","-e","tcp.srcport","-e","tcp.payload"],capture_output=True,text=True,check=True)
    streams = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts)==3 and parts[2]:
            key=(parts[0],parts[1])
            streams.setdefault(key,bytearray()).extend(bytes.fromhex(parts[2].replace(":","")))
    frames=[]
    for key,data in streams.items():
        offset=0
        while offset+4<=len(data):
            size=int.from_bytes(data[offset:offset+4],"big")
            if size==0 or offset+4+size>len(data):break
            frames.append((key,bytes(data[offset+4:offset+4+size])))
            offset+=4+size
    wire=b"".join(data for data in streams.values())
    if b"16002216-16003727-16004417-16005162" not in wire:
        raise RuntimeError("capture lacks the final GROUP handshake")
    if b"GROUP_1" in wire:raise RuntimeError("legacy GROUP in capture")
    if scenario=="plain" and (b"login_interactive_start" not in wire or b'"op":"spend"' not in wire):
        raise RuntimeError("plaintext login/request not observed")
    if scenario=="secure" and (b"login_interactive_start" in wire or b'"op":"spend"' in wire):
        raise RuntimeError("secure capture exposed application plaintext")
    if scenario=="A1" and len({key[0] for key in streams})<3:
        raise RuntimeError("capture lacks A1 peer connections")
    repeats=0
    for key in streams:
        encrypted=[frame for k,frame in frames if k==key and len(frame)>=28 and frame[:1]!=b"{"]
        repeats+=len(encrypted)-len(set(encrypted))
    if scenario=="replay" and repeats<1:raise RuntimeError("replayed encrypted frame not observed")
    return {"payload_packets":len(result.stdout.splitlines()), "tcp_streams":len({k[0] for k in streams}),
            "reassembled_frames":len(frames),"repeated_ciphertexts":repeats,"group_verified":True,
            "filter":FILTER,"scenario":scenario}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario",choices=list(NAMES),default="secure")
    parser.add_argument("--interface",required=True,help="tshark -D loopback interface number/name")
    parser.add_argument("--tshark",default=shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe")
    parser.add_argument("--duration",type=int,default=45)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    if not Path(args.tshark).exists() and not shutil.which(args.tshark):parser.error("tshark unavailable; see README manual capture steps")
    output=args.output or BASE/"runtime"/"evidence"/(NAMES[args.scenario]+"-"+secrets.token_hex(5))
    output.mkdir(parents=True,exist_ok=False)
    work=BASE/"runtime"/"capture-runs"/secrets.token_hex(8)
    capture=output/(NAMES[args.scenario]+".pcapng")
    proc=subprocess.Popen([args.tshark,"-i",args.interface,"-f","tcp port 5050 or tcp port 6000",
            "-a",f"duration:{args.duration}","-w",str(capture)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    lines=queue.Queue()
    def read():
        for line in proc.stderr:lines.put(line)
    thread=threading.Thread(target=read,daemon=True);thread.start()
    try:
        deadline=time.monotonic()+15
        while True:
            line=lines.get(timeout=max(.1,deadline-time.monotonic()))
            if "Capturing on" in line:break
            if proc.poll() is not None or time.monotonic()>deadline:raise RuntimeError("capture did not start: "+line)
        start=time.monotonic()
        run=subprocess.run([sys.executable,"-m","treasury.demo",args.scenario,"--run-dir",str(work)],cwd=BASE,
                           capture_output=True,text=True,timeout=240)
        if run.returncode:raise RuntimeError(run.stdout+run.stderr)
        if time.monotonic()-start>=args.duration:raise RuntimeError("scenario exceeded capture duration; rerun with longer --duration")
        proc.wait(timeout=args.duration+15)
        if proc.returncode:raise RuntimeError("tshark capture failed")
        shutil.copytree(work/"logs",output/"logs",ignore=shutil.ignore_patterns("*.stdout","*.process-output"))
        shutil.copyfile(work/"result.json",output/"result.json")
        validation=inspect_capture(args.tshark,capture,args.scenario)
        sources={str(p.relative_to(BASE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((BASE/"treasury").glob("*.py"))}
        validation.update(created_utc=datetime.now(timezone.utc).isoformat(),source_hashes=sources)
        (output/"validation.json").write_text(json.dumps(validation,indent=2),encoding="utf-8")
        print(json.dumps({"evidence":str(output),**{k:v for k,v in validation.items() if k!="source_hashes"}},sort_keys=True))
    finally:
        if proc.poll() is None:proc.terminate();proc.wait(timeout=5)
        thread.join(timeout=2)
        proc.stderr.close()


if __name__=="__main__":main()
