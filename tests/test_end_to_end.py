"""Independent CLI processes; controller reads results only, never owner secrets."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.parametrize("scenario,args", [
    ("secure",[]),("vault",[]),("vault",["--n","4","--t","2"]),
    ("vault",["--n","5","--t","4"]),("vote",[]),
    ("A1",[]),("A5",[]),("A7",[]),("replay",[])])
def test_actual_cli_workflows(tmp_path,scenario,args):
    root=tmp_path/"run"
    result=subprocess.run([sys.executable,"-m","treasury.demo",scenario,"--run-dir",str(root),*args],
                          cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=240)
    assert result.returncode==0,result.stdout+result.stderr
    outcome=json.loads((root/"result.json").read_text())
    assert outcome["scenario"]==scenario
    assert (root/"logs"/"founder.log").exists()
    assert (root/"logs"/"server.log").exists()
    # Only per-member processes may create/read their own login secret/share.
    server=(root/"data"/"server")
    assert not (server/"share.json").exists()
    assert not (server/"login.secret").exists()
