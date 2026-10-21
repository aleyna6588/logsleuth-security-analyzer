
import re
import csv
import io
from collections import Counter

import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="LogSleuth",
    page_icon="🔎",
    layout="wide",
)

st.title("🔎 LogSleuth")
st.write("A Python security log analysis dashboard")
st.caption("Educational prototype — flags are review signals, not proof of attacks.")

SAMPLE_LOG = """Oct 21 09:01:11 server sshd: Failed password for admin from 192.0.2.10 port 5123 ssh2
Oct 21 09:01:15 server sshd: Failed password for root from 192.0.2.10 port 5124 ssh2
Oct 21 09:01:19 server sshd: Failed password for guest from 192.0.2.10 port 5125 ssh2
Oct 21 09:02:10 server sshd: Accepted password for user from 192.0.2.25 port 6000 ssh2
Oct 21 09:03:12 server sshd: Failed password for test from 198.51.100.7 port 4000 ssh2
"""

with st.sidebar:
    st.header("Settings")
    threshold = st.slider(
        "Failed attempts per IP to flag",
        min_value=1,
        max_value=20,
        value=3,
    )
    uploaded = st.file_uploader(
        "Upload a .log or .txt file",
        type=["log", "txt"],
    )

if uploaded:
    log_text = uploaded.getvalue().decode("utf-8", errors="replace")
    source_name = uploaded.name
else:
    log_text = SAMPLE_LOG
    source_name = "Built-in sample logs"

pattern = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(\S+) from "
    r"(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

failed_events = []
total_lines = 0

for line_number, line in enumerate(log_text.splitlines(), start=1):
    total_lines += 1
    match = pattern.search(line)

    if match:
        username, ip = match.groups()
        octets = ip.split(".")

        if all(0 <= int(part) <= 255 for part in octets):
            failed_events.append({
                "Line": line_number,
                "Username": username,
                "IP Address": ip,
                "Log Entry": line,
            })

ip_counts = Counter(
    event["IP Address"] for event in failed_events
)

flagged = {
    ip: count
    for ip, count in ip_counts.most_common()
    if count >= threshold
}

st.info(f"Analyzing: {source_name}")

st.subheader("Security Overview")
c1, c2, c3, c4 = st.columns(4)

c1.metric("Lines analyzed", total_lines)
c2.metric("Failed logins", len(failed_events))
c3.metric("Unique source IPs", len(ip_counts))
c4.metric("IPs flagged", len(flagged))

if flagged:
    st.warning(
        f"{len(flagged)} IP address(es) reached "
        f"the threshold of {threshold} failed attempts."
    )
else:
    st.success("No IP addresses reached the selected threshold.")

left, right = st.columns(2)

with left:
    st.subheader("Failed Attempts by IP")
    if ip_counts:
        chart = pd.DataFrame(
            list(ip_counts.items()),
            columns=["IP Address", "Attempts"],
        ).set_index("IP Address")
        st.bar_chart(chart)
    else:
        st.write("No matching failed-login events found.")

with right:
    st.subheader("Flagged Addresses")
    if flagged:
        st.dataframe(
            pd.DataFrame([
                {
                    "IP Address": ip,
                    "Failed Attempts": count,
                }
                for ip, count in flagged.items()
            ]),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.write("No flagged addresses.")

st.subheader("Failed Login Events")

if failed_events:
    events_df = pd.DataFrame(failed_events)

    search = st.text_input("Filter by username or IP")
    if search:
        mask = events_df.astype(str).apply(
            lambda column: column.str.contains(
                search, case=False, regex=False
            )
        ).any(axis=1)
        events_df = events_df[mask]

    st.dataframe(
        events_df,
        use_container_width=True,
        hide_index=True,
    )

    csv_buffer = io.StringIO()
    events_df.to_csv(csv_buffer, index=False)

    st.download_button(
        "Download CSV Report",
        data=csv_buffer.getvalue(),
        file_name="logsleuth-report.csv",
        mime="text/csv",
    )
else:
    st.write("No failed-login events to display.")

with st.expander("About this project"):
    st.write(
        "LogSleuth is an educational prototype that recognizes "
        "a limited SSH failed-password log pattern. A flagged IP "
        "is not necessarily malicious. This tool does not block "
        "traffic or perform real-time intrusion detection."
    )
