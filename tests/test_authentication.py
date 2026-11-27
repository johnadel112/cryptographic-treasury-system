"""Essam's registration/login/request scenarios migrated to treasury, plus regressions."""
import json
from concurrent.futures import ThreadPoolExecutor
import pytest
from conftest import client
from treasury.client import TreasuryMemberClient
from treasury.config import P, Q, G, GROUP
from treasury.encoding import H
from treasury.login import make_commitment, load_login_secret
from treasury.requests import sign_request
from treasury.application import TreasuryApplication
from treasury.identity import load_identity


def test_group_parameters():
    assert P.bit_length() == 2048 and P == 2*Q+1 and G == 4
    assert pow(G, Q, P) == 1


def test_registration_and_no_replacement(env):
    root, port, app = env
    with TreasuryMemberClient("M1", data_dir=root, port=port) as c:
        assert c.register()["ok"]
        assert not c.register()["ok"]
        assert not c.exchange({"type":"register", "X_M": format(pow(G,12345,P),"x")})["ok"]
    assert load_login_secret("M1", root) != load_identity("M1",root).private_key.private_numbers().private_value


@pytest.mark.parametrize("value", ["0", "1", "-1", "0x10", "ABC", "00", format(P-1,"x"), format(P,"x"), 3, None])
def test_invalid_registration_group_elements(env, value):
    root, port, app = env
    with TreasuryMemberClient("M1", data_dir=root, port=port) as c:
        assert not c.exchange({"type":"register", "X_M":value})["ok"]
    assert app.store.snapshot()["members"] == {}


def test_both_logins_and_single_use_nonce(env):
    root, port, app = env
    for method in ["interactive", "noninteractive"]:
        c = client(root, port, method=method)
        c.close()
    with TreasuryMemberClient("M1", data_dir=root, port=port) as c:
        N = int(c.exchange({"type":"login_noninteractive_nonce"})["N"],16)
        x = load_login_secret("M1",root)
        k, R = make_commitment()
        e = H("login", "M1", pow(G,x,P), R, N, q=Q)
        proof = {"type":"login_noninteractive", "R":format(R,"x"), "z":format((k+e*x)%Q,"x")}
        assert c.exchange(proof)["ok"]
        assert not c.exchange(proof)["ok"]
        assert not c.request("ping",{})["ok"]  # failed relogin clears authentication


def test_nonce_bound_to_connection(env):
    root, port, _ = env
    a = client(root,port)
    b = client(root,port)
    try:
        N = int(a.exchange({"type":"login_noninteractive_nonce"})["N"],16)
        x = load_login_secret("M1",root)
        k,R = make_commitment(); e=H("login","M1",pow(G,x,P),R,N,q=Q)
        proof={"type":"login_noninteractive","R":format(R,"x"),"z":format((k+e*x)%Q,"x")}
        assert not b.exchange(proof)["ok"]
        assert a.exchange(proof)["ok"]
    finally:
        a.close();b.close()


def test_invalid_login_proof_and_stage(env):
    root,port,_=env
    with TreasuryMemberClient("M1",data_dir=root,port=port) as c:
        c.register()
        assert not c.exchange({"type":"login_interactive_finish","z":"0"})["ok"]
        assert not c.exchange({"type":"login_interactive_start","R":"1"})["ok"]
        c.exchange({"type":"login_interactive_start","R":format(G,"x")})
        assert not c.exchange({"type":"login_interactive_finish","z":format(Q,"x")})["ok"]
        assert not c.request("ping",{})["ok"]


def test_signed_requests_seq_replay_modification_and_ledger(env):
    root,port,app=env
    with TreasuryMemberClient("M2",data_dir=root,port=port) as c:
        assert not c.request("spend", {"amount":50,"reason":"pizza"},seq=1)["ok"]
        assert c.login()["ok"]
        assert c.request("spend", {"amount":50,"reason":"pizza"},seq=1)["ok"]
        assert not c.request("spend", {"amount":50,"reason":"pizza"},seq=1)["ok"]
        bad=sign_request(c.identity.private_key,GROUP,"M2",2,"spend",{"amount":50,"reason":"pizza"})
        bad["body"]["amount"]=5000
        assert not c.exchange(bad)["ok"]
    state=app.store.snapshot()
    assert len(state["ledger"])==1 and state["last_seq"]["M2"]==1


def test_failed_operation_does_not_consume_seq_or_append_ledger(env):
    root,port,app=env
    c=client(root,port)
    try:
        assert not c.request("spend", {"amount":-2,"reason":"bad"},seq=1)["ok"]
        assert not c.request("invented", {},seq=1)["ok"]
        assert app.store.snapshot()["ledger"] == []
        assert c.request("ping",{},seq=1)["ok"]
    finally:
        c.close()


def test_concurrent_same_sequence_exactly_one_acceptance(env):
    root,port,app=env
    clients=[client(root,port),client(root,port)]
    try:
        with ThreadPoolExecutor(2) as pool:
            results=list(pool.map(lambda c:c.request("spend",{"amount":1,"reason":"race"},seq=1),clients))
        assert sum(r["ok"] for r in results)==1
        assert len(app.store.snapshot()["ledger"])==1
    finally:
        for c in clients:c.close()


def test_persisted_registry_sequences_and_ledger(env):
    root,port,app=env
    c=client(root,port)
    assert c.request("ping",{})["ok"]
    c.close()
    restored=TreasuryApplication(root,load_identity("server",root),app.log)
    assert restored.store.snapshot()==app.store.snapshot()
    c=client(root,port,method="noninteractive")
    assert c.seq==1 and c.request("ping",{})["ok"]
    c.close()
