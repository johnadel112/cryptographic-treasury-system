"""Dashboard checks use the real authenticated TCP service, not mocked balances."""
from pathlib import Path
import json
import pytest
from dashboard.service import MemberDashboard, OwnerConfig, DashboardError
from treasury.client import TreasuryMemberClient

APP = str(Path(__file__).resolve().parents[1] / "dashboard" / "app.py")


def configured(monkeypatch, root, port):
    monkeypatch.setenv("TREASURY_DASHBOARD_MEMBER", "M1")
    monkeypatch.setenv("TREASURY_DASHBOARD_DATA", str(root))
    monkeypatch.setenv("TREASURY_DASHBOARD_PORT", str(port))


def test_overview_requires_login_and_projects_public_fields(env):
    root, port, app = env
    with TreasuryMemberClient("M1", data_dir=root, port=port) as c:
        assert not c.request("overview", {})["ok"]
    dashboard = MemberDashboard(OwnerConfig("M1", root, port))
    opening = dashboard.execute("open-vault")
    for name in ("M1", "M3", "M5"):
        MemberDashboard(OwnerConfig(name, root, port)).execute("contribute", operation=opening["id"])
    snapshot = dashboard.execute("overview")
    row = snapshot["operations"][0]
    assert row["state"] == "opened" and row["has_contribution"]
    assert row["contribution_count"] == 3
    forbidden = {"content_hex", "contributions", "ballots", "sig", "proof", "d_i", "share"}
    def inspect(value):
        if isinstance(value, dict):
            assert forbidden.isdisjoint(value)
            for child in value.values(): inspect(child)
        elif isinstance(value, list):
            for child in value: inspect(child)
    inspect(snapshot)
    assert all(set(entry) == {"time", "member", "seq", "op"} for entry in snapshot["ledger"])


def test_dashboard_owner_isolation_and_both_logins(env, monkeypatch):
    root, port, app = env
    original = Path.read_bytes
    def guarded(path):
        resolved = path.resolve()
        for name in ("M2", "M3", "M4", "M5"):
            if resolved.is_relative_to((root / name).resolve()):
                raise AssertionError("dashboard read another member's private directory")
        return original(path)
    monkeypatch.setattr(Path, "read_bytes", guarded)
    for method in ("interactive", "noninteractive"):
        assert MemberDashboard(OwnerConfig("M1", root, port), method).execute("overview")["n"] == 5
    with pytest.raises(DashboardError):
        MemberDashboard(OwnerConfig("M1", root, port)).execute("arbitrary-command")


def test_dashboard_missing_setup_and_recorded_evidence(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest
    configured(monkeypatch, tmp_path, 5050)
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    assert not at.session_state.connected
    at.button(key="connect").click().run()
    assert not at.exception and at.error
    at.radio(key="page").set_value("Evidence").run()
    assert not at.exception and at.json
    at.button(key="clear").click().run()
    assert not at.session_state.connected and not at.exception


def test_dashboard_rejects_weakened_handshake_without_ui_crash(setup_root, service_factory, monkeypatch):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest
    app, port = service_factory(setup_root, weaknesses=("unsigned-handshake",))
    configured(monkeypatch, setup_root, port)
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.button(key="connect").click().run()
    assert not at.exception and at.error
    assert not at.session_state.connected
    assert "validation failed" in at.error[0].value


def test_dashboard_real_vault_vote_and_rejections(env, monkeypatch):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest
    root, port, app = env
    configured(monkeypatch, root, port)
    at = AppTest.from_file(APP, default_timeout=40).run()
    at.button(key="connect").click().run()
    assert not at.exception and at.session_state.connected
    at.radio(key="page").set_value("Vault").run()
    at.button(key="open_vault").click().run()
    opening = at.session_state.snapshot["operations"][0]["id"]
    at.button(key="contribute_" + opening).click().run()
    assert at.button(key="contribute_" + opening).disabled
    for name in ("M3", "M5"):
        MemberDashboard(OwnerConfig(name, root, port)).execute("contribute", operation=opening)
    at.button(key="connect").click().run()
    at.button(key="retrieve").click().run()
    assert at.session_state.download[1] == b"integrated treasury treasure"
    assert not at.exception
    at.radio(key="page").set_value("Voting").run()
    at.text_input[0].set_value("Evaluation supplies")
    next(b for b in at.button if b.label == "Create signed spending request").click().run()
    assert not at.exception
    vote = next(op for op in at.session_state.snapshot["operations"] if op["kind"] == "vote")
    next(r for r in at.radio if r.label == "Your private ballot").set_value("Approve")
    next(b for b in at.button if b.label == "Encrypt and submit ballot").click().run()
    assert not at.exception
    for name, value in [("M2", 0), ("M3", 1), ("M4", 0), ("M5", 1)]:
        MemberDashboard(OwnerConfig(name, root, port)).execute("ballot", vote_number=vote["vote_number"], vote=value)
    # Signature/identity checks still reject a duplicate in the underlying client.
    with pytest.raises(DashboardError, match="closed|duplicate"):
        MemberDashboard(OwnerConfig("M1", root, port)).execute("ballot", vote_number=vote["vote_number"], vote=0)
    for name in ("M2", "M3"):
        MemberDashboard(OwnerConfig(name, root, port)).execute("contribute", operation=vote["id"])
    at.button(key="connect").click().run()
    at.button(key="contribute_" + vote["id"]).click().run()
    assert not at.exception
    assert any(m.label == "Yes" and m.value == "3" for m in at.metric)
    assert any(m.label == "Decision" and m.value == "Approved" for m in at.metric)
    assert '"vote":' not in json.dumps(at.session_state.events)
    at.radio(key="page").set_value("Activity").run()
    assert not at.exception and at.dataframe
    at.button(key="clear").click().run()
    assert not at.session_state.connected
    assert "download" not in at.session_state
