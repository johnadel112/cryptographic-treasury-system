"""Streamlit entry point. Launch with python -m treasury.dashboard."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))
import streamlit as st
from dashboard.service import DashboardError, MemberDashboard, OwnerConfig, event

st.set_page_config(page_title="Treasury | Member workspace", page_icon="T", layout="wide")
st.markdown("""<style>
.block-container {max-width:1200px;padding-top:2.5rem;padding-bottom:3rem;}
[data-testid="stSidebar"] {background:#10243a;}
[data-testid="stSidebar"] * {color:#e6eef7;}
[data-testid="stSidebar"] [data-baseweb="select"] * {color:#14263d;}
[data-testid="stSidebar"] a {background:#21425e;color:#e6eef7!important;border-color:#42637d;}
[data-testid="stSidebar"] button {background:#21425e;border-color:#42637d;}
[data-testid="stMetric"] {background:white;border:1px solid #dde5ed;border-radius:12px;padding:18px;}
[data-testid="stMetricValue"] {font-weight:650;}
h1,h2,h3 {letter-spacing:-.025em;}
[data-testid="stVerticalBlockBorderWrapper"] {border-radius:12px;}
</style>""", unsafe_allow_html=True)

try:
    owner = OwnerConfig.from_environment()
except ValueError:
    st.error("Invalid owner configuration. Start the dashboard with a valid member name and port.")
    st.stop()

for key, value in {"connected": False, "snapshot": {}, "events": [], "last_sync": None}.items():
    if key not in st.session_state:
        st.session_state[key] = value


def record(action, accepted, detail):
    st.session_state.events = [event(action, accepted, detail), *st.session_state.events][:100]


def service():
    return MemberDashboard(owner, st.session_state.get("login_method", "interactive"))


def refresh():
    try:
        st.session_state.snapshot = service().execute("overview")
        st.session_state.connected = True
        st.session_state.last_sync = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        return True
    except DashboardError as exc:
        st.session_state.connected = False
        st.session_state.pop("download", None)
        st.session_state.notice = ("error", str(exc))
        record("Refresh", False, str(exc))
        return False


def mutate(action, **values):
    try:
        result = service().execute(action, **values)
        label = {"open-vault": "Opening requested", "spend": "Vote created", "ballot": "Encrypted ballot accepted",
                 "contribute": "Contribution accepted"}[action]
        detail = result.get("id", "")
        record(action, True, detail or label)
        st.session_state.notice = ("success", f"{label}. {detail}")
        refresh()
    except DashboardError as exc:
        record(action, False, str(exc))
        st.session_state.notice = ("error", str(exc))



def create_spend():
    reason = st.session_state.spend_reason.strip()
    if not reason:
        st.session_state.notice = ("warning", "Enter a reason for this spending request.")
    else:
        mutate("spend", amount=st.session_state.spend_amount, reason=reason)


def cast_ballot(operation, vote_number):
    choice = st.session_state.get("ballot_" + operation)
    if choice is None:
        st.session_state.notice = ("warning", "Choose approve or reject before submitting.")
    else:
        mutate("ballot", vote_number=vote_number, vote=int(choice == "Approve"))


with st.sidebar:
    st.markdown("## TREASURY")
    st.caption("ICS505 | MEMBER WORKSPACE")
    st.divider()
    st.markdown(f"### {owner.name}")
    st.caption("Fixed owner | localhost only")
    page = st.radio("Workspace", ["Overview", "Vault", "Voting", "Activity", "Evidence"], label_visibility="collapsed", key="page")
    st.divider()
    st.selectbox("Login method", ["interactive", "noninteractive"], key="login_method",
                 format_func=lambda x: "Interactive Schnorr" if x == "interactive" else "Non-interactive Schnorr")
    if st.button("Connect / refresh", width="stretch", type="primary", key="connect"):
        with st.spinner("Verifying identity and signing the snapshot request..."):
            if refresh():
                st.session_state.notice = ("success", "Identity verified. Treasury snapshot refreshed.")
        st.rerun()
    st.toggle("Automatic refresh (5 seconds)", value=True, key="auto_refresh")
    hub = os.environ.get("TREASURY_LAB_HUB")
    if hub:
        st.link_button("All member workspaces", hub, width="stretch")
    if st.button("Clear session", width="stretch", key="clear"):
        for key in list(st.session_state):
            del st.session_state[key]
        st.session_state.auto_attempted = True
        st.rerun()
    st.caption(f"Treasury endpoint: 127.0.0.1:{owner.port}")
    st.caption("Every action uses a fresh authenticated, encrypted connection.")

if os.environ.get("TREASURY_DASHBOARD_AUTOCONNECT") == "1" and not st.session_state.get("auto_attempted"):
    st.session_state.auto_attempted = True
    refresh()

notice = st.session_state.pop("notice", None)
if notice:
    getattr(st, notice[0])(notice[1])

st.caption("CRYPTOGRAPHIC TREASURY / " + page.upper())
headers = {"Overview": ("Your treasury, together.", "A shared vault. Independent members. Every decision verified."),
           "Vault": ("Open with a quorum.", "Contribute your share without exposing it to the treasury server."),
           "Voting": ("Private votes. Shared decisions.", "Encrypt your ballot locally. Reveal only the final aggregate."),
           "Activity": ("A record of accepted actions.", "Review the signed ledger and this browser's recent outcomes."),
           "Evidence": ("Security you can inspect.", "Recorded local demonstrations from the integrated protocol.")}
st.title(headers[page][0])
st.write(headers[page][1])

if page == "Evidence":
    st.info("Recorded evidence from the integration run, not a live security status. Capture source hashes identify the code used at collection time.")
    scenario = st.selectbox("Demonstration", ["secure", "plain", "A1", "A5", "A7", "A3", "replay"])
    descriptions = {
        "secure": "Both login methods and signed spending requests over encrypted transport.",
        "plain": "Deliberately disabled encryption makes application messages visible.",
        "A1": "Unsigned handshake exposes traffic; signed requests still resist changes. Secure handshake rejects Mallory.",
        "A5": "The same cheating M3 contribution fails recovery without proofs; verified proofs reject it and M4 substitutes.",
        "A7": "Changed unsigned ballot produces 3 yes; signed ballot rejects the change and produces 2. Both runs use the same unsigned-handshake carrier.",
        "A3": "Guessed short challenge versus fresh 128-bit challenges. Observed attempts are not an exhaustive security proof.",
        "replay": "A duplicated encrypted frame is rejected by the receive counter."}
    st.write(descriptions[scenario])
    folder = BASE / "captures" / "integrated" / scenario
    try:
        outcome = json.loads((folder / "result.json").read_text("utf-8"))
        st.json(outcome, expanded=True)
        validation = folder / "validation.json"
        if validation.exists():
            measured = json.loads(validation.read_text("utf-8"))
            c1, c2, c3 = st.columns(3)
            c1.metric("TCP streams", measured["tcp_streams"])
            c2.metric("Reassembled frames", measured["reassembled_frames"])
            c3.metric("Repeated ciphertexts", measured["repeated_ciphertexts"])
            st.caption("Captured " + measured["created_utc"])
            capture = next(folder.glob("*.pcapng"))
            st.download_button("Download packet capture", capture.read_bytes(), file_name=capture.name, mime="application/octet-stream")
        else:
            st.caption("This scenario has program logs and measured results; no packet capture is claimed.")
        log = folder / "logs" / "server.log"
        if log.exists():
            with st.expander("Matching treasury log"):
                st.code(log.read_text("utf-8"), language="text")
        st.code("tcp.port == 5050 || tcp.port == 6000", language="text")
    except (OSError, ValueError, StopIteration):
        st.warning("This evidence bundle is unavailable. Restore captures/integrated from the repository.")
    st.stop()

if not st.session_state.connected:
    with st.container(border=True):
        st.subheader("Connect your member workspace")
        st.write(f"This process acts as **{owner.name}**. Start the treasury server, then use **Connect / refresh** in the sidebar.")
        st.code(f"python -m treasury.server --data-dir {owner.root}", language="text")
        st.caption("Your member identity, founder-issued certificate and vault setup must already exist. No sample balances or simulated approvals are shown.")
    with st.expander("First-time setup"):
        st.write("Follow the independent owner setup in README.md. For multiple members, launch a separate dashboard process and browser port for each owner.")
        st.code("python -m treasury.dashboard --name M2 --data-dir runtime/live1 --port 8502", language="text")
    st.stop()



def choose_operation(kind, states=None):
    available = [op for op in st.session_state.snapshot["operations"] if op["kind"] == kind and (states is None or op["state"] in states)]
    if not available:
        st.info("No matching operations yet. Create one or refresh after another member acts.")
        return None
    lookup = {op["id"]: op for op in reversed(available)}
    selected = st.selectbox("Operation", list(lookup), format_func=lambda x: f"{x} | {lookup[x]['state']}", key=f"selected_{kind}")
    return lookup[selected]


def progress(operation):
    t = st.session_state.snapshot["t"]
    st.write("Verified contributors: " + (", ".join(operation.get("contributors", [])) or "None yet"))
    c1, c2 = st.columns(2)
    c1.metric("State", operation["state"].capitalize())
    c2.metric("Verified contributions", f"{operation['contribution_count']} / {t}")
    st.progress(min(operation["contribution_count"] / t, 1.0), text=f"{t} unique valid contributions required")
    if operation["state"] == "collecting":
        st.caption("Your contribution has been accepted." if operation["has_contribution"] else "Your share stays in this member process. Only the partial decryption and proof are sent.")
        st.button("Contribute my share", type="primary", disabled=operation["has_contribution"],
                  key=f"contribute_{operation['id']}", on_click=mutate, args=("contribute",),
                  kwargs={"operation": operation["id"]})


if page == "Vault":
    with st.container(border=True):
        st.subheader("Start an opening")
        st.write("Create ONE opening, then every participant selects that same operation below. Do not create a separate opening for each member.")
        st.button("Request vault opening", type="primary", key="open_vault", on_click=mutate, args=("open-vault",))
elif page == "Voting":
    with st.expander("Create a spending vote", expanded=not any(op["kind"] == "vote" for op in st.session_state.snapshot["operations"])):
        with st.form("spend_form", clear_on_submit=True):
            st.number_input("Amount (whole units)", min_value=1, max_value=1_000_000_000, value=50, step=1, key="spend_amount")
            st.text_input("Reason", max_chars=500, placeholder="What should the treasury fund?", key="spend_reason")
            st.form_submit_button("Create signed spending request", type="primary", on_click=create_spend)



@st.fragment(run_every=5 if st.session_state.get("auto_refresh", True) else None)
def live_workspace():
    notice = st.session_state.pop("notice", None)
    if notice:
        getattr(st, notice[0])(notice[1])
    if not refresh():
        st.error(st.session_state.notice[1])
        st.caption("Check the server and use Connect / refresh. No contribution or ballot is automatically retried.")
        return
    snapshot = st.session_state.snapshot
    operations = snapshot["operations"]
    n, t = snapshot["n"], snapshot["t"]
    st.caption(f"Last verified snapshot: {st.session_state.last_sync} | {owner.name} | {t}-of-{n} threshold | Automatic refresh every 5 seconds" if st.session_state.get("auto_refresh", True) else f"Last verified snapshot: {st.session_state.last_sync} | Automatic refresh paused")
    if page == "Overview":
        a, b, c, d = st.columns(4)
        a.metric("Threshold", f"{t} of {n}")
        b.metric("Open votes", sum(op["kind"] == "vote" and op["state"] in ("voting", "collecting") for op in operations))
        c.metric("Vaults opened", sum(op["kind"] == "vault" and op["state"] == "opened" for op in operations))
        d.metric("Accepted requests", snapshot["ledger_total"])
        st.subheader("Current operations")
        if operations:
            rows = [{"Operation": op["id"], "Type": op["kind"].capitalize(), "State": op["state"],
                     "Ballots": f"{op['ballot_count']}/{n}" if op["kind"] == "vote" else "-",
                     "Contributions": f"{op['contribution_count']}/{t}"} for op in reversed(operations)]
            st.dataframe(rows, hide_index=True, width="stretch")
        else:
            st.info("A fresh treasury. Request a vault opening or create the first spending vote.")
        left, right = st.columns(2)
        with left, st.container(border=True):
            st.subheader("Threshold vault")
            st.write(f"Gather {t} verified contributions to recover the encrypted file. No treasury secret is reconstructed.")
        with right, st.container(border=True):
            st.subheader("Private spending")
            st.write(f"All {n} members cast encrypted ballots. At least 3 yes votes approve spending, independently of the decryption threshold.")
        st.caption(f"Showing the latest {len(operations)} of {snapshot['operation_total']} operations. Counts above reflect this window; accepted requests reflect the full ledger before this refresh.")
        with st.expander("Verified configuration"):
            st.code(snapshot["group"], language="text")
            st.write("Founder-signed setup | P-256 identities and ECDH | AES-256-GCM transport | Schnorr login")

    elif page == "Vault":
        st.subheader("Opening progress")
        operation = choose_operation("vault")
        if operation:
            progress(operation)
            if operation["state"] == "failed":
                st.error("Recovery failed. Review the treasury log; no valid recovered file is available.")
            if operation["state"] == "opened":
                st.success("Threshold reached. The file was authenticated and recovered.")
                if st.button("Retrieve recovered file", key="retrieve"):
                    try:
                        result = service().execute("status", operation=operation["id"])
                        if result.get("state") != "opened" or "content_hex" not in result:
                            raise DashboardError("No recovered file is available for this operation.")
                        st.session_state.download = (operation["id"], bytes.fromhex(result["content_hex"]))
                    except (DashboardError, ValueError) as exc:
                        st.error(str(exc))
                download = st.session_state.get("download")
                if download and download[0] == operation["id"]:
                    st.download_button("Download recovered file", download[1], file_name="treasury-recovered.bin", mime="application/octet-stream")
                    st.caption("Available only in this member's browser session. Clear session removes the in-memory download.")

    elif page == "Voting":
        st.subheader("Vote workspace")
        operation = choose_operation("vote")
        if operation:
            st.write(f"**{operation['amount']} units**")
            st.text(operation["reason"])
            st.progress(operation["ballot_count"] / n, text=f"{operation['ballot_count']} of {n} encrypted ballots received")
            if operation["state"] == "voting":
                if operation["has_ballot"]:
                    st.success("Your encrypted ballot has been accepted. Individual choices remain private.")
                else:
                    choice = st.radio("Your private ballot", ["Approve", "Reject"], index=None, horizontal=True, key="ballot_" + operation["id"])
                    st.button("Encrypt and submit ballot", type="primary", on_click=cast_ballot,
                              args=(operation["id"], operation["vote_number"]))
            elif operation["state"] == "finalized":
                yes = operation["total"]
                a, b, c = st.columns(3)
                a.metric("Yes", yes)
                b.metric("No", n - yes)
                c.metric("Decision", "Approved" if operation["approved"] else "Rejected")
                st.bar_chart({"Ballots": {"Yes": yes, "No": n - yes}}, color="#087f6b")
                st.caption("The aggregate was threshold-decrypted. This chart does not identify any member's choice.")
            elif operation["state"] == "failed":
                st.error("The aggregate could not be validated. No spending approval is issued.")
            if operation["state"] in ("collecting", "finalized"):
                progress(operation)
        with st.expander("How privacy works"):
            st.write("Ballots use fresh ElGamal randomness and member signatures. The server combines ciphertexts; members decrypt only the aggregate. Approval requires at least three yes votes. Signatures do not prove that a malicious ballot encodes 0 or 1; a zero-knowledge bit-validity proof is outside this assignment implementation.")

    elif page == "Activity":
        st.subheader("Accepted treasury ledger")
        st.caption("Latest 100 accepted requests, before this snapshot request. Signature/proof payloads are omitted. Refresh itself is a signed request.")
        if snapshot["ledger"]:
            st.dataframe(list(reversed(snapshot["ledger"])), hide_index=True, width="stretch")
        else:
            st.info("No earlier accepted requests.")
        st.subheader("This browser session")
        st.caption("Local action outcomes, including rejections. No individual vote choices are recorded here.")
        if st.session_state.events:
            st.dataframe(st.session_state.events, hide_index=True, width="stretch")
            st.download_button("Download public action events", json.dumps(st.session_state.events, indent=2), file_name="member-events.json", mime="application/json")
        else:
            st.info("Submit an action to see its result here.")


live_workspace()
