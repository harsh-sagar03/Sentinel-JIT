# =============================================================================
# app.py  —  Sentinel-JIT Security Dashboard
# =============================================================================
# Run with:  python3 -m streamlit run app.py
# =============================================================================

import time
from datetime import datetime
from typing import Any, Dict, List, Tuple
import streamlit as st
import risk_engine
import ai_analysis

st.set_page_config(
    page_title="Sentinel-JIT | Security Dashboard",
    page_icon="shield",
    layout="wide",
)

# ---------------------------------------------------------------------------
# CSS — premium dark theme  (Datadog / Vercel inspired)
# ---------------------------------------------------------------------------
FONT_URL = (
    "https://fonts.googleapis.com/css2?"
    "family=Inter:wght@400;500;600;700;800&display=swap"
)
st.markdown(
    f"<link rel='stylesheet' href='{FONT_URL}'>",
    unsafe_allow_html=True
)

st.markdown("""
<style>
/* ─── Base ─── */
html, body,
[data-testid="stAppViewContainer"],
[data-testid="stHeader"] {
    background-color: #0a0a0a !important;
    font-family: 'Inter', -apple-system, sans-serif !important;
    color: #d4d4d4 !important;
}
[data-testid="stSidebar"]  { display: none !important; }
[data-testid="block-container"] {
    padding: 1.5rem 2.8rem 2rem !important;
    max-width: 1440px;
}
footer { visibility: hidden; }

/* ─── Typography ─── */
h1 {
    font-size: 1.65rem !important;
    font-weight: 800 !important;
    color: #f0f0f0 !important;
    -webkit-text-fill-color: #f0f0f0 !important;
    letter-spacing: -0.03em;
    margin: 0 !important;
}
h2 {
    font-size: 0.72rem !important;
    font-weight: 700 !important;
    color: #666666 !important;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    border-bottom: 1px solid #242424;
    padding-bottom: 0.45rem;
    margin-bottom: 0.9rem !important;
}
hr { border-color: #1e1e1e !important; margin: 1.4rem 0 !important; }

/* ─── Streamlit Metric card ─── */
[data-testid="stMetric"] {
    background: #141414;
    border: 1px solid #242424;
    border-radius: 8px;
    padding: 1rem 1.1rem;
}
[data-testid="stMetricLabel"] p {
    color: #666666 !important;
    font-size: 0.68rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.1em;
    text-transform: uppercase;
}
[data-testid="stMetricValue"] {
    color: #e2e2e2 !important;
    font-size: 1.35rem !important;
    font-weight: 700 !important;
}

/* ─── Download button ─── */
[data-testid="stDownloadButton"] > button {
    background: #b91c1c !important;
    color: #fff !important;
    border: none !important;
    border-radius: 6px !important;
    font-weight: 700 !important;
    font-size: 0.76rem !important;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 0.52rem 1.3rem !important;
}
[data-testid="stDownloadButton"] > button:hover {
    background: #991b1b !important;
}

/* ─── Expander ─── */
[data-testid="stExpander"] {
    background: #141414;
    border: 1px solid #242424 !important;
    border-radius: 8px;
}

/* ─── Alert banners ─── */
.banner-high {
    background: #180a0a;
    border-left: 3px solid #dc2626;
    border-top: 1px solid #2a1010;
    border-right: 1px solid #2a1010;
    border-bottom: 1px solid #2a1010;
    border-radius: 0 6px 6px 0;
    padding: 0.7rem 1rem;
    color: #fca5a5;
    font-size: 0.85rem;
    font-weight: 500;
}
.banner-ok {
    background: #0a150c;
    border-left: 3px solid #16a34a;
    border-top: 1px solid #102314;
    border-right: 1px solid #102314;
    border-bottom: 1px solid #102314;
    border-radius: 0 6px 6px 0;
    padding: 0.7rem 1rem;
    color: #86efac;
    font-size: 0.85rem;
    font-weight: 500;
}

/* ─── Stage badges ─── */
.badge {
    display: inline-block;
    background: #1e1e1e;
    border: 1px solid #333333;
    color: #888888;
    font-size: 0.67rem;
    font-weight: 700;
    letter-spacing: 0.07em;
    padding: 0.15rem 0.55rem;
    border-radius: 4px;
    margin: 0.12rem 0.1rem;
    text-transform: uppercase;
}

/* ─── Narrative card ─── */
.narr-card {
    background: #141414;
    border: 1px solid #242424;
    border-radius: 8px;
    padding: 1.2rem 1.4rem;
    color: #888888;
    font-size: 0.855rem;
    line-height: 1.85;
}
.narr-card .narr-lbl {
    font-size: 0.67rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: #555555;
    margin-bottom: 0.9rem;
}
.narr-card p { margin: 0.55rem 0; color: #999999; }
.narr-card .concl {
    margin-top: 0.9rem;
    padding: 0.7rem 0.9rem;
    background: #0a0a0a;
    border: 1px solid #242424;
    border-radius: 5px;
    font-size: 0.82rem;
    color: #666666;
}

/* ─── HTML table ─── */
.cmd-table {
    width: 100%;
    border-collapse: collapse;
    background: #141414;
    border: 1px solid #242424;
    border-radius: 8px;
    overflow: hidden;
    font-size: 0.82rem;
}
.cmd-table th {
    background: #0a0a0a;
    color: #666666;
    font-size: 0.67rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid #242424;
    text-align: left;
}
.cmd-table td {
    padding: 0.45rem 0.75rem;
    border-bottom: 1px solid #1c1c1c;
    vertical-align: middle;
}
.cmd-table tr:last-child td { border-bottom: none; }
.cmd-table tr:hover td { background: #1a1a1a; }
.td-idx  { color: #444444; font-size: 0.75rem; width: 2rem; }
.td-ts   { color: #555555; font-size: 0.78rem; white-space: nowrap; }
.td-cmd  {
    font-family: 'SF Mono', 'Fira Mono', monospace;
    color: #d4d4d4;
    background: #111111;
    border-radius: 4px;
    padding: 0.15rem 0.45rem;
    font-size: 0.79rem;
    display: inline-block;
}
.td-stage { color: #666666; }

/* ─── Chip strip (incident report) ─── */
.chips { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-bottom: 1rem; }
.chip {
    background: #141414;
    border: 1px solid #242424;
    border-radius: 7px;
    padding: 0.65rem 0.9rem;
    flex: 1 1 110px;
}
.chip .cl { color: #555555; font-size: 0.65rem; font-weight:700;
    text-transform:uppercase; letter-spacing:0.1em; margin-bottom:0.2rem; }
.chip .cv { color: #e2e2e2; font-size: 0.88rem; font-weight: 700; }

/* ─── Actions card ─── */
.act-card {
    background: #141414;
    border: 1px solid #242424;
    border-radius: 8px;
    padding: 0.85rem 1rem;
    margin-bottom: 1rem;
}
.act-lbl {
    font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.1em; color: #555555; margin-bottom: 0.6rem;
}
.act-row {
    display: flex; gap: 0.65rem; align-items: flex-start;
    padding: 0.32rem 0; border-bottom: 1px solid #1c1c1c;
    font-size: 0.84rem; color: #666666;
}
.act-row:last-child { border-bottom: none; }
.act-n { color: #dc2626; font-weight: 700; min-width: 1.2rem; }

/* ─── Footer banner ─── */
.footer-bar {
    text-align: center;
    background: #1a1400;
    border: 1px solid #fbbf24;
    border-radius: 6px;
    padding: 0.5rem 1rem;
    margin-top: 0.4rem;
}
.footer-bar span {
    font-size: 0.75rem; font-weight: 800;
    letter-spacing: 0.15em; text-transform: uppercase;
    color: #fbbf24;
}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def get_source_ip(events: List[Dict[str, str]]) -> str:
    for e in events:
        if isinstance(e, dict) and e.get("ip"):
            return str(e["ip"])
    return "Unknown"


def extract_narrative(
    report: str,
) -> Tuple[List[str], List[str]]:
    """Return (body_paragraphs, conclusion_sentences)."""
    paragraphs: List[str] = []
    conclusion: List[str] = []
    in_concl = False
    skip_keys = {
        "ATTACK BEHAVIOR", "Threat Intelligence",
        "Total commands", "Attack stages detected",
        "NARRATIVE SUMMARY", "Sentinel-JIT", "CONCLUSION",
        "Recommended Action:",
    }
    for line in report.split("\n"):
        s = line.strip()
        if not s or s.startswith("=") or s.startswith("-"):
            continue
        if any(k in s for k in skip_keys):
            if "CONCLUSION" in s:
                in_concl = True
            continue
        if in_concl:
            conclusion.append(s)
        elif len(s) > 20:
            paragraphs.append(s)
    return paragraphs, conclusion


def load_all_data() -> Dict[str, Any]:
    events = risk_engine.load_logs()
    risk_score = risk_engine.calculate_risk_score(events)
    decision = risk_engine.decoy_decision(risk_score)
    commands = ai_analysis.extract_attacker_commands(events)
    analysis = ai_analysis.analyze_attack(commands)
    report = ai_analysis.generate_report(analysis)
    return {
        "events":          events,
        "source_ip":       get_source_ip(events),
        "failed_logins":   int(risk_engine.count_failed_logins(events)),
        "cmd_count":       int(risk_engine.count_attacker_commands(events)),
        "risk_score":      int(risk_score),
        "risk_level":      str(decision["risk_level"]),
        "decoy_triggered": bool(decision["decoy_triggered"]),
        "analysis":        analysis,
        "report":          str(report),
    }


# ---------------------------------------------------------------------------
# HEADER
# ---------------------------------------------------------------------------
live_badge = (
    "<div style='background:#1a0b0b;border:1px solid #7f1d1d;"
    "border-radius:5px;padding:0.3rem 0.8rem;"
    "font-size:0.7rem;font-weight:700;letter-spacing:0.12em;"
    "color:#f87171'>LIVE MONITORING</div>"
)
st.markdown(
    "<div style='display:flex;align-items:center;"
    "justify-content:space-between;padding:0.2rem 0 1rem'>"
    "<div>"
    "<h1>Sentinel-JIT</h1>"
    "<span style='color:#334155;font-size:0.72rem;"
    "letter-spacing:0.16em;text-transform:uppercase;font-weight:600'>"
    "Autonomous Just-In-Time Deception Security System</span>"
    "</div>"
    + live_badge +
    "</div>",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# DATA
# ---------------------------------------------------------------------------
data = load_all_data()
if not data["events"]:
    st.error("No data. Run 'python3 run_demo.py' first.")
    st.stop()


# ===========================================================================
# SECTION 1 — THREAT OVERVIEW
# ===========================================================================
st.header("Threat Overview")

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Attacker IP", data["source_ip"])
c2.metric("Failed Logins", data["failed_logins"])
c3.metric("Commands Run", data["cmd_count"])
c4.metric("Risk Score", f"{data['risk_score']} / 100")
c5.metric("Risk Level", data["risk_level"])
c6.metric("Decoy", "TRIGGERED" if data["decoy_triggered"] else "INACTIVE")

# Custom dark progress bar
risk = data["risk_score"]
st.markdown(
    f"<div style='margin:1rem 0 0.5rem;display:flex;"
    f"align-items:center;gap:0.9rem'>"
    f"<span style='font-size:0.67rem;color:#334155;"
    f"font-weight:700;letter-spacing:0.12em;"
    f"text-transform:uppercase'>Risk Score</span>"
    f"<span style='color:#dc2626;font-weight:800;"
    f"font-size:0.92rem'>{risk}/100</span>"
    f"<span style='color:#1e2538;font-size:0.75rem'>"
    f"threshold: 70</span></div>"
    f"<div style='background:#1a1f30;border-radius:3px;"
    f"height:5px;width:100%'>"
    f"<div style='background:linear-gradient(90deg,#dc2626,#b91c1c);"
    f"width:{risk}%;height:100%;border-radius:3px'></div></div>",
    unsafe_allow_html=True,
)
st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)

if data["decoy_triggered"]:
    st.markdown(
        "<div class='banner-high'>HIGH RISK — Attacker silently redirected"
        " into decoy environment. All commands are being captured.</div>",
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        "<div class='banner-ok'>System nominal — "
        "risk below threshold. No decoy deployed.</div>",
        unsafe_allow_html=True,
    )
st.divider()


# ===========================================================================
# SECTION 2 — ATTACK INTELLIGENCE
# ===========================================================================
st.header("Attack Intelligence")

attacker_events: List[Dict[str, str]] = [
    e for e in data["events"]
    if isinstance(e, dict) and e.get("type") == "attacker_command"
]

col_l, col_r = st.columns([10, 9], gap="large")

with col_l:
    st.markdown(
        "<p style='font-size:0.67rem;color:#334155;font-weight:700;"
        "text-transform:uppercase;letter-spacing:0.1em;"
        "margin-bottom:0.5rem'>Command Timeline</p>",
        unsafe_allow_html=True,
    )

    # Build HTML table rows
    thead = (
        "<tr>"
        "<th class='cmd-table' style='width:2.5rem'>#</th>"
        "<th class='cmd-table'>Timestamp</th>"
        "<th class='cmd-table'>Command</th>"
        "<th class='cmd-table'>Attack Stage</th>"
        "</tr>"
    )
    tbody = ""
    for i, item in enumerate(data["analysis"]):
        if not isinstance(item, dict):
            continue
        ts_raw = (
            attacker_events[i]["timestamp"]
            if i < len(attacker_events) else "N/A"
        )
        tbody += (
            "<tr>"
            f"<td><span class='td-idx'>{i + 1}</span></td>"
            f"<td><span class='td-ts'>{ts_raw}</span></td>"
            f"<td><span class='td-cmd'>{item['command']}</span></td>"
            f"<td><span class='td-stage'>{item['stage']}</span></td>"
            "</tr>"
        )

    st.markdown(
        f"<table class='cmd-table'>{thead}{tbody}</table>",
        unsafe_allow_html=True,
    )

    # Stage badges
    stage_counts: Dict[str, int] = {}
    for item in data["analysis"]:
        if isinstance(item, dict):
            s = str(item["stage"])
            stage_counts[s] = stage_counts.get(s, 0) + 1
    badges = "".join(
        f"<span class='badge'>{s} ({c})</span>"
        for s, c in stage_counts.items()
    )
    st.markdown(
        f"<div style='margin-top:0.6rem'>{badges}</div>",
        unsafe_allow_html=True,
    )

with col_r:
    st.markdown(
        "<p style='font-size:0.67rem;color:#334155;font-weight:700;"
        "text-transform:uppercase;letter-spacing:0.1em;"
        "margin-bottom:0.5rem'>AI Attack Narrative</p>",
        unsafe_allow_html=True,
    )
    paragraphs, conclusion = extract_narrative(data["report"])
    body_html = "".join(f"<p>{p}</p>" for p in paragraphs)
    concl_html = (
        "<div class='concl'>" + " ".join(conclusion) + "</div>"
        if conclusion else ""
    )
    st.markdown(
        f"<div class='narr-card'>"
        f"<div class='narr-lbl'>Analyst Summary</div>"
        f"{body_html}{concl_html}</div>",
        unsafe_allow_html=True,
    )

st.divider()


# ===========================================================================
# SECTION 3 — INCIDENT REPORT
# ===========================================================================
st.header("Incident Report")
st.markdown(
    "<p style='color:#334155;font-size:0.82rem;margin:-0.5rem 0 0.9rem'>"
    "Official record — suitable for escalation to management, "
    "SOC, or law enforcement.</p>",
    unsafe_allow_html=True,
)

# Chip strip
decoy_str = "YES — Decoy active" if data["decoy_triggered"] else "NO"
chips_data = [
    ("IP Address",    data["source_ip"]),
    ("Failed Logins", str(data["failed_logins"])),
    ("Commands Run",  str(data["cmd_count"])),
    ("Risk Score",    f"{data['risk_score']} / 100"),
    ("Risk Level",    data["risk_level"]),
    ("Decoy",         decoy_str),
]
chips_html = "".join(
    f"<div class='chip'><div class='cl'>{lbl}</div>"
    f"<div class='cv'>{val}</div></div>"
    for lbl, val in chips_data
)
st.markdown(
    f"<div class='chips'>{chips_html}</div>",
    unsafe_allow_html=True,
)

# Recommended actions
actions = [
    "Block the attacker's IP address at the firewall immediately.",
    "Escalate this incident to the Security Operations Center (SOC).",
    "Review all files and directories accessed in the decoy.",
    "Rotate credentials for all accounts on the affected system.",
    "Preserve all logs for forensic and legal investigation.",
]
rows_html = "".join(
    f"<div class='act-row'><span class='act-n'>{i+1}.</span>"
    f"<span>{a}</span></div>"
    for i, a in enumerate(actions)
)
st.markdown(
    f"<div class='act-card'><div class='act-lbl'>"
    f"Recommended Actions</div>{rows_html}</div>",
    unsafe_allow_html=True,
)

# Build download file
stage_summary: Dict[str, List[str]] = {}
for item in data["analysis"]:
    if isinstance(item, dict):
        s = str(item["stage"])
        if s not in stage_summary:
            stage_summary[s] = []
        stage_summary[s].append(str(item["command"]))

sep = "=" * 55
thin = "-" * 55
yes_no = "YES" if data["decoy_triggered"] else "NO"
txt = sep + "\n  SENTINEL-JIT INCIDENT REPORT\n" + sep + "\n\n"
txt += "Attacker IP     : " + data["source_ip"] + "\n"
txt += "Failed Logins   : " + str(data["failed_logins"]) + "\n"
txt += "Commands Run    : " + str(data["cmd_count"]) + "\n"
txt += "Risk Score      : " + str(data["risk_score"]) + " / 100\n"
txt += "Risk Level      : " + data["risk_level"] + "\n"
txt += "Decoy Triggered : " + yes_no + "\n\n"
txt += "ATTACK STAGES\n" + thin + "\n"
for s, cmds in stage_summary.items():
    txt += "  [" + s + "]\n"
    for c in cmds:
        txt += "    - " + c + "\n"
txt += "\nRECOMMENDED ACTIONS\n" + thin + "\n"
for i, a in enumerate(actions):
    txt += "  " + str(i + 1) + ". " + a + "\n"
txt += "\n" + sep + "\n  Report by Sentinel-JIT\n" + sep + "\n"

st.download_button(
    label="Download Incident Report (.txt)",
    data=txt,
    file_name="sentinel_jit_incident_report.txt",
    mime="text/plain",
)

st.divider()
st.markdown(
    "<div class='footer-bar'>"
    "<span>Sentinel-JIT &nbsp;|&nbsp; Hackathon Prototype"
    " &nbsp;|&nbsp; For Demonstration Purposes Only</span>"
    "</div>",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# LIVE AUTO-REFRESH — re-reads logs.json every 1 second
# ---------------------------------------------------------------------------
last_updated = datetime.now().strftime("%H:%M:%S")
st.markdown(
    f"<p style='text-align:center;color:#333333;font-size:0.65rem;"
    f"margin-top:0.4rem'>⟳ Live &nbsp;|&nbsp; Last updated: {last_updated}</p>",
    unsafe_allow_html=True,
)
time.sleep(1)
st.rerun()
