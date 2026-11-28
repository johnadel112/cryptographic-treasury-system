"""Public process launcher. Never imports a member client or loads credentials."""
import json
import os
from pathlib import Path
from datetime import datetime, timezone
import streamlit as st

st.set_page_config(page_title="Treasury | Demonstration hub", page_icon="T", layout="wide")
st.markdown("<style>.block-container{max-width:1200px;padding-top:2rem;}h1,h2,h3{letter-spacing:-.025em;}</style>", unsafe_allow_html=True)
st.caption("ICS505 / LIVE DEMONSTRATION")
st.title("One treasury. Five independent members.")
st.write("Open each member in its own tab. All five workspaces use the same encrypted treasury, while keys and shares remain with their owners.")
root_value = os.environ.get("TREASURY_LAB_ROOT")
if not root_value:
    st.error("Start the complete system with start_demo.cmd.")
    st.stop()
root = Path(root_value)


def request_launch(name):
    if name not in ("M1", "M2", "M3", "M4", "M5"):
        raise ValueError("invalid member")
    (root / "control" / ("launch-" + name)).touch()


@st.fragment(run_every=2)
def cards():
    try:
        status = json.loads((root / "lab.json").read_text("utf-8"))
        fresh = (datetime.now(timezone.utc) - datetime.fromisoformat(status["updated"])).total_seconds() < 8
    except (OSError, ValueError, KeyError):
        st.warning("Waiting for the demonstration launcher. Keep its terminal running.")
        return
    if not fresh:
        st.warning("The launcher is not responding. Restart start_demo.cmd; the existing runtime is preserved.")
    if not status["server_running"]:
        st.error("Treasury server is stopped. Restart the lab from its terminal.")
    st.caption(f"Shared treasury: 127.0.0.1:{status['server_port']} | 3 valid contributions required | Workspace availability refreshes every 2 seconds")
    columns = st.columns(5)
    for column, member in zip(columns, status["members"]):
        name = member["name"]
        with column, st.container(border=True):
            st.subheader(name)
            running = fresh and member["running"]
            ready = running and member["ready"]
            st.caption("Running" if ready else "Starting..." if running else "Stopped / unavailable")
            st.write(f"Port {member['port']}")
            st.link_button(f"Open {name}", f"http://127.0.0.1:{member['port']}", disabled=not ready, type="primary", width="stretch")
            if st.button(f"Launch {name}", disabled=running or not fresh, width="stretch"):
                request_launch(name)
                st.info("Launch requested. The Open button will become available shortly.")
    if st.button("Launch all stopped workspaces", disabled=not fresh):
        for member in status["members"]:
            if not member["running"]:
                request_launch(member["name"])
        st.success("Requested. Running workspaces are kept unchanged.")


cards()
st.divider()
a, b = st.columns(2)
with a, st.container(border=True):
    st.subheader("1. Open the same vault together")
    st.markdown("1. Open M1, choose **Vault**, and request **one** opening.\n2. Open M3 and M5, choose **Vault**, and select that same operation ID.\n3. Each member presses **Contribute my share** once.\n4. Watch verified contributor names appear automatically. After the third valid contribution, retrieve the recovered file.")
    st.caption("Two contributions stay collecting. Each proof is checked by the actual treasury server.")
with b, st.container(border=True):
    st.subheader("2. Decide on spending privately")
    st.markdown("1. M1 creates a spending vote under **Voting**.\n2. Each of M1-M5 opens that same vote and submits its own encrypted ballot.\n3. After all five ballots, three members contribute to the aggregate decryption.\n4. The final tally appears automatically. Three or more yes votes approve spending.")
    st.caption("Individual ballot choices never appear on this central page.")
with st.expander("Evaluation controls and runtime"):
    st.write("The hub starts or opens processes only. It never logs in as a member, reads member keys or shares, or submits contributions. Workspaces authenticate independently on opening and every action.")
    st.write("Use Ctrl+C in the startup terminal, or start_demo.cmd --stop from another terminal, to stop the entire lab. Restarting resumes the same runtime; use --run-dir runtime/lab-new for a fresh evaluation.")
    st.code(str(root), language="text")
