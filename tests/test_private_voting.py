"""Real encrypted ballots, operation lifecycle and threshold-only aggregate tally."""
import pytest
from conftest import client,setup_test_root
from treasury.config import G,P
from treasury.voting import make_ballot,encrypt_vote,recover_yes_count


@pytest.mark.parametrize("votes",[(1,1,1,1,1),(0,0,0,0,0),(1,0,1,0,1),(1,0,0,1,0)])
def test_private_vote_outcomes(env,votes,caplog):
    root,port,app=env
    caplog.set_level("INFO")
    c=client(root,port)
    vote=c.request("spend",{"amount":50,"reason":"pizza"})["result"]
    c.close()
    for i,value in enumerate(votes,1):
        c=client(root,port,f"M{i}",method="noninteractive")
        response=c.ballot(vote["vote_number"],value)
        c.close()
        assert response["ok"]
    for i in [1,3,5]:
        c=client(root,port,f"M{i}")
        result=c.contribute(vote["id"])
        c.close()
        assert result["ok"]
        if i!=5:assert result["result"]["state"]=="collecting"
    assert result["result"]["total"]==sum(votes)
    assert result["result"]["approved"]==(sum(votes)>=3)
    stored=app.store.snapshot()["operations"][vote["id"]]
    assert all(set(b)<= {"type","vote_number","c1","c2","sig"} for b in stored["ballots"].values())
    assert not any("plaintext vote" in record.message or "vote_yes" in record.message for record in caplog.records)


def test_ballot_lifecycle_signatures_and_duplicates(env):
    root,port,app=env
    c=client(root,port)
    assert not c.ballot(999,0)["ok"]
    vote=c.request("spend",{"amount":2,"reason":"club"})["result"]["vote_number"]
    ballot=make_ballot(c.identity.private_key,c.name,vote,0,int(app.vault["vault_key"],16))
    modified=dict(ballot,c2=format(int(ballot["c2"],16)*G%P,"x"))
    assert not c.exchange(modified)["ok"]
    assert not c.exchange(dict(ballot,c1="1"))["ok"]
    assert not c.exchange(dict(ballot,vote_number=True))["ok"]
    assert c.exchange(ballot)["ok"]
    assert not c.exchange(ballot)["ok"]
    c.close()
    for i in range(2,6):
        c=client(root,port,f"M{i}");assert c.ballot(vote,0)["ok"];c.close()
    c=client(root,port)
    assert not c.exchange(ballot)["ok"]
    c.close()


def test_ballots_require_login(env):
    from treasury.client import TreasuryMemberClient
    root,port,app=env
    with TreasuryMemberClient("M1",data_dir=root,port=port) as c:
        assert not c.ballot(1,0)["ok"]


def test_vote_randomness_and_out_of_range_tally(env):
    _,_,app=env
    h=int(app.vault["vault_key"],16)
    assert encrypt_vote(1,h)!=encrypt_vote(1,h)
    with pytest.raises(ValueError):encrypt_vote(5,h)
    with pytest.raises(ValueError):recover_yes_count(pow(G,6,P),5)
    assert recover_yes_count(1,5)==0


def test_threshold_two_does_not_change_three_yes_approval(tmp_path,service_factory):
    root=setup_test_root(tmp_path,4,2)
    app,port=service_factory(root)
    c=client(root,port);vote=c.request("spend",{"amount":1,"reason":"test"})["result"];c.close()
    for i,v in enumerate([1,1,0,0],1):
        c=client(root,port,f"M{i}");assert c.ballot(vote["vote_number"],v)["ok"];c.close()
    for i in [1,2]:
        c=client(root,port,f"M{i}");r=c.contribute(vote["id"]);c.close()
    assert r["result"]["total"]==2 and not r["result"]["approved"]
