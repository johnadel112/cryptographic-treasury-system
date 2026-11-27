"""Reproducible local evaluation runner. All participants are independent CLIs.

The controller never reads identity keys, login secrets or member shares.
Each run writes to a NEW directory; no existing runtime/evidence is deleted.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time


class Demo:
    def __init__(self, root: Path, n=5, t=3):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=False)
        self.data = self.root / "data"
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.env = dict(os.environ, TREASURY_LOG_DIR=str(self.logs))
        self.n, self.t = n, t
        self.processes = []
        self.streams = []
        self.count = 0

    def run(self, module, *args, success=True):
        result = subprocess.run([sys.executable,"-m","treasury."+module,*args],
                                capture_output=True,text=True,env=self.env,timeout=60)
        self.count += 1
        (self.logs/f"{self.count:03d}-{module}.stdout").write_text(result.stdout,encoding="utf-8")
        if success and result.returncode != 0:
            raise RuntimeError(f"{module} failed: {result.stderr[-2000:]}")
        if not success and result.returncode == 0:
            raise RuntimeError(f"{module} unexpectedly succeeded")
        return result

    def setup(self):
        self.run("server","--init-identity","--data-dir",str(self.data))
        for i in range(1,self.n+1):
            self.run("member","--name",f"M{i}","--init-identity","--data-dir",str(self.data))
        content=self.root/"input.txt"
        content.write_bytes(b"integrated treasury treasure")
        self.run("founder","--n",str(self.n),"--t",str(self.t),"--data-dir",str(self.data),"--vault-file",str(content))

    def launch(self,module,*args):
        output=(self.logs/f"{module}.process-output").open("a",encoding="utf-8")
        self.streams.append(output)
        path=self.logs/f"{module}.log"
        before=path.stat().st_size if path.exists() else 0
        process=subprocess.Popen([sys.executable,"-m","treasury."+module,*args],env=self.env,
                                 stdout=output,stderr=output)
        self.processes.append(process)
        path=self.logs/f"{module}.log"
        deadline=time.monotonic()+15
        # Log files append across server restarts; require a newly written listening line.
        while time.monotonic()<deadline:
            if path.exists():
                with path.open("r",encoding="utf-8") as stream:
                    stream.seek(before)
                    if "listening on" in stream.read():return process
            if process.poll() is not None:raise RuntimeError(f"{module} exited before listening")
            time.sleep(.05)
        raise RuntimeError(f"{module} did not start")

    def stop(self):
        for process in self.processes:
            if process.poll() is None:process.terminate()
            process.wait(timeout=5)
        self.processes.clear()
        for stream in self.streams:stream.close()
        self.streams.clear()

    def server(self,*weaknesses):
        flags=[item for weakness in weaknesses for item in ("--weak",weakness)]
        return self.launch("server","--data-dir",str(self.data),*flags)

    def member(self,name="M1",command="login",*args,weaknesses=(),success=True,port=5050):
        flags=[item for weakness in weaknesses for item in ("--weak",weakness)]
        result=self.run("member","--name",name,"--data-dir",str(self.data),"--port",str(port),
                        "--command",command,*args,*flags,success=success)
        if not result.stdout.strip():return {"ok":False}
        return json.loads(result.stdout.strip().splitlines()[-1])

    def vault(self):
        self.server()
        combinations=[("M1","M3","M5"),("M2","M4","M5")] if (self.n,self.t)==(5,3) else [tuple(f"M{i}" for i in range(1,self.t+1))]
        for index,names in enumerate(combinations):
            operation=self.member(command="open-vault")["result"]["id"]
            for j,name in enumerate(names):
                output=self.root/f"recovered-{index}.bin"
                r=self.member(name,"contribute","--operation",operation,"--output",str(output))
                expected="opened" if j==self.t-1 else "collecting"
                if r["result"]["state"]!=expected:raise RuntimeError("threshold behavior mismatch")
            if output.read_bytes()!=(self.root/"input.txt").read_bytes():raise RuntimeError("vault content mismatch")
        return {"scenario":"vault","n":self.n,"t":self.t,"combinations":len(combinations),"recovery":"verified"}

    def vote(self,votes):
        self.server()
        record=self.member(command="spend")["result"]
        for i,value in enumerate(votes,1):
            self.member(f"M{i}","ballot","--vote-number",str(record["vote_number"]),"--vote",str(value),"--login","noninteractive")
        for i in range(1,self.t+1):
            result=self.member(f"M{i}","contribute","--operation",record["id"])["result"]
            if i<self.t and result["state"]!="collecting":raise RuntimeError("threshold bypass")
        if result["total"]!=sum(votes) or result["approved"]!=(sum(votes)>=3):raise RuntimeError("incorrect tally")
        return {"scenario":"vote","total":result["total"],"approved":result["approved"]}

    def a1(self):
        self.server("unsigned-handshake")
        self.member(weaknesses=["unsigned-handshake"])
        self.launch("mallory","--attack","A1","--weak","unsigned-handshake","--tamper-request")
        self.member(command="spend",weaknesses=["unsigned-handshake"],port=6000,success=False)
        self.stop()
        log=(self.logs/"mallory.log").read_text("utf-8")
        if "login_interactive_finish" not in log or "changed signed request" not in log:
            raise RuntimeError("A1 did not observe/tamper integrated authentication/request")
        if "request signature or sequence verification FAILED" not in (self.logs/"server.log").read_text("utf-8"):
            raise RuntimeError("signed request tampering not rejected")
        self.server()
        self.launch("mallory","--attack","A1")
        self.member(port=6000,success=False)
        if "hs-server signature verification FAILED" not in (self.logs/"M1.log").read_text("utf-8"):
            raise RuntimeError("secure handshake failed for unexpected reason")
        return {"scenario":"A1","login_exposed":True,"signed_request_tamper":"rejected","secure_handshake":"rejected"}

    def a5(self):
        for weak in (True,False):
            self.server(*(["no-proof"] if weak else []))
            operation=self.member(command="open-vault")["result"]["id"]
            for name in ["M1","M2"]:
                self.member(name,"contribute","--operation",operation)
            result=self.member("M3","contribute","--operation",operation,"--cheat","A5",success=weak)
            if weak:
                if result["result"]["state"]!="failed":raise RuntimeError("A5 weak vault unexpectedly recovered")
            else:
                if "proof verification FAILED" not in result.get("error",""):raise RuntimeError("A5 rejected for wrong reason")
                result=self.member("M4","contribute","--operation",operation,"--output",str(self.root/"A5-recovered.bin"))
                if result["result"]["state"]!="opened":raise RuntimeError("A5 substitution failed")
                if (self.root/"A5-recovered.bin").read_bytes()!=(self.root/"input.txt").read_bytes():raise RuntimeError("A5 content mismatch")
            self.stop()
        return {"scenario":"A5","weak":"vault recovery failed","secure":"M3 rejected; M4 substituted; recovered"}

    def a7(self):
        totals=[]
        for unsigned in (True,False):
            # Keep A1 carrier identical in both runs to isolate application signatures.
            flags=["unsigned-handshake"]+(["unsigned-ballots"] if unsigned else [])
            self.server(*flags)
            vote=self.member(command="spend",weaknesses=flags)["result"]
            self.member(weaknesses=flags)
            self.launch("mallory","--attack","A7","--weak","unsigned-handshake")
            response=self.member("M1","ballot","--vote-number",str(vote["vote_number"]),"--vote","0",weaknesses=flags,port=6000,success=unsigned)
            if not unsigned:
                if "ballot signature" not in response.get("error",""):raise RuntimeError("A7 wrong rejection")
                self.member("M1","ballot","--vote-number",str(vote["vote_number"]),"--vote","0",weaknesses=flags)
            for i,value in enumerate([1,0,1,0],2):
                self.member(f"M{i}","ballot","--vote-number",str(vote["vote_number"]),"--vote",str(value),weaknesses=flags)
            for name in ["M1","M3","M5"]:
                result=self.member(name,"contribute","--operation",vote["id"],weaknesses=flags)["result"]
            totals.append(result["total"])
            self.stop()
        if totals!=[3,2]:raise RuntimeError(f"A7 unexpected totals {totals}")
        return {"scenario":"A7","weak_total":3,"signed_total":2,"signed_tamper":"rejected"}

    def auth(self,plain=False):
        flags=["no-encryption"] if plain else []
        self.server(*flags)
        for name,method in [("M1","interactive"),("M2","noninteractive")]:
            self.member(name,"request","--login",method,"--op","spend","--body",'{"amount":50,"reason":"pizza"}',weaknesses=flags)
        return {"scenario":"plain" if plain else "secure","both_logins":"verified","signed_requests":"accepted"}

    def replay(self):
        self.server()
        self.member()
        self.launch("mallory","--attack","replay-frame")
        self.member(port=6000,success=False)
        time.sleep(.2)
        if "nonce validation FAILED" not in (self.logs/"server.log").read_text("utf-8"):raise RuntimeError("replay not rejected")
        return {"scenario":"replay","result":"nonce replay rejected"}

    def a3(self):
        attempts=[]
        for weak in (True,False):
            self.server(*(["short-challenge"] if weak else []))
            self.member("M3")
            response=self.member("M3","a3","--attempts","256" if weak else "8",success=weak)
            attempts.append(response["attempts"])
            self.stop()
        return {"scenario":"A3","weak_attempts":attempts[0],"secure_rejected_attempts":attempts[1]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario",choices=["secure","plain","vault","vote","A1","A5","A7","A3","replay"])
    parser.add_argument("--run-dir",type=Path)
    parser.add_argument("--n",type=int,default=5)
    parser.add_argument("--t",type=int,default=3)
    parser.add_argument("--votes",default="1,0,1,0,1")
    args=parser.parse_args()
    if not 1<=args.t<=args.n:parser.error("require 1<=t<=n")
    if args.scenario in ("A5","A7","A3") and (args.n,args.t)!=(5,3):parser.error("attack scenario requires default 3-of-5")
    root=args.run_dir or Path("runtime")/"demos"/(args.scenario+"-"+secrets.token_hex(6))
    demo=Demo(root,args.n,args.t)
    try:
        demo.setup()
        if args.scenario=="vote":
            votes=[int(v) for v in args.votes.split(",")]
            if len(votes)!=args.n or any(v not in (0,1) for v in votes):raise ValueError("one 0/1 vote per member required")
            result=demo.vote(votes)
        elif args.scenario in ("secure","plain"):
            result=demo.auth(args.scenario=="plain")
        else:
            result=getattr(demo,args.scenario.lower())()
        (root/"result.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
        print(json.dumps({"run_dir":str(root),**result},sort_keys=True))
    finally:
        demo.stop()


if __name__=="__main__":main()
