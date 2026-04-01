import streamlit as st
from data.scenarios import SCENARIOS

# ---------------------------
# PAGE CONFIG
# ---------------------------
st.set_page_config(
    page_title="Threat & Response Command Center",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------
# HELPERS
# ---------------------------
def safe_list(value):
    return value if isinstance(value, list) else []


def safe_dict(value):
    return value if isinstance(value, dict) else {}


def first_n(items, n):
    return safe_list(items)[:n]


def build_risk_lens(snapshot: dict, validation_items: list[str], signals: dict) -> tuple[str, list[str]]:
    concern = snapshot.get("initial_concern", "")
    business_impact = snapshot.get("business_impact", "")
    team_context = snapshot.get("team_context", "")

    signal_categories = [k.replace("_", " ").title() for k, v in signals.items() if safe_list(v)]
    signal_summary = ", ".join(signal_categories[:3]) if signal_categories else "available telemetry"

    short_body = (
        "Treat this as a potentially meaningful event until ownership, follow-on activity, "
        "and downstream impact are validated."
    )

    details = []

    if concern:
        details.append(f"Core concern: {concern}")

    if validation_items:
        details.append(f"First validation priority: {validation_items[0]}")

    details.append(f"Primary telemetry to review: {signal_summary}")

    if business_impact:
        details.append(f"Why it matters: {business_impact}")

    if "privileged" in team_context.lower() or "privileged" in snapshot.get("observed_activity", "").lower():
        details.append("Privilege level raises urgency because the account may reach higher-value systems or workflows.")

    if "unusual" in team_context.lower() or "foreign" in snapshot.get("observed_activity", "").lower():
        details.append("The access pattern does not align cleanly with normal behavior, so the risk is not just the event itself but what it may have enabled next.")

    return short_body, details


def build_timeline_explanations(snapshot: dict, timeline_steps: list[str]) -> list[dict]:
    explanations = []
    concern = snapshot.get("initial_concern", "")
    objective = snapshot.get("attacker_objective", "")
    impact = snapshot.get("business_impact", "")

    for i, step in enumerate(timeline_steps, start=1):
        lower_step = step.lower()

        if any(word in lower_step for word in ["credential", "phishing", "targeted", "stolen"]):
            explainer = [
                "This is often the setup phase where the attacker obtains the initial way in.",
                "At this point, activity may still be low visibility except for early identity or delivery signals.",
                "If the entry method is identity-based, it may look like normal access at first.",
            ]
        elif any(word in lower_step for word in ["login", "access", "session", "approval"]):
            explainer = [
                "This is where the attacker converts access into a usable session or foothold.",
                "The main question is whether the event stayed isolated or led to follow-on actions.",
                f"Why this matters now: {concern}" if concern else "Why this matters now: this is often where suspicious becomes actionable.",
            ]
        elif any(word in lower_step for word in ["review", "map", "enumerate", "discover", "test"]):
            explainer = [
                "This phase usually reflects reconnaissance or environment familiarization.",
                "The attacker is trying to understand what they can reach, what has value, and what can be used next.",
                f"Likely objective at this stage: {objective}" if objective else "Likely objective at this stage: expand understanding before taking noisier action.",
            ]
        elif any(word in lower_step for word in ["privilege", "expand", "pivot", "lateral", "persistence"]):
            explainer = [
                "This is where the incident can grow beyond the initial access point.",
                "Blast radius tends to increase quickly once privilege, persistence, or lateral movement begins.",
                "Containment decisions become more urgent here because waiting can make later response much harder.",
            ]
        elif any(word in lower_step for word in ["data", "exfil", "mailbox", "storage", "impact", "fraud"]):
            explainer = [
                "This stage suggests the attacker is beginning to extract value from the intrusion.",
                f"Potential outcome: {impact}" if impact else "Potential outcome: operational, financial, or data exposure impact.",
                "At this point, business stakeholders may need to be involved alongside the technical team.",
            ]
        else:
            explainer = [
                "This step represents part of the likely attacker progression for the scenario.",
                "Use it to align the room on what may already have happened and what could happen next.",
                "It is most useful when paired with the signals and validation questions already shown above.",
            ]

        next_step = timeline_steps[i] if i < len(timeline_steps) else "Containment, validation, and impact scoping become the next priority."
        explainer.append(f"Likely next phase: {next_step}")

        explanations.append(
            {
                "step_number": i,
                "step_text": step,
                "details": explainer,
            }
        )

    return explanations


def render_metric_tile(label: str, value: str, accent: str = "orange") -> None:
    st.markdown(
        f"""
        <div class="metric-tile accent-{accent}">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_context_panel(title: str, body: str, accent: str = "orange") -> None:
    st.markdown(
        f"""
        <div class="context-panel accent-{accent}">
            <div class="context-title">{title}</div>
            <div class="context-body">{body}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_list_card(title: str, items: list[str], accent: str = "green") -> None:
    bullets = "".join(f"<li>{item}</li>" for item in items)
    st.markdown(
        f"""
        <div class="trcc-card accent-{accent}">
            <div class="trcc-section-title">{title}</div>
            <ul class="trcc-list">
                {bullets}
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_guidance_block(signal_name: str, content: dict) -> None:
    looks_like = "".join(
        f"<li>{item}</li>" for item in safe_list(content.get("what_it_looks_like", []))
    )
    tam_response = "".join(
        f"<li>{item}</li>" for item in safe_list(content.get("tam_response", []))
    )
    questions = "".join(
        f"<li>{item}</li>" for item in safe_list(content.get("questions_to_ask", []))
    )

    st.markdown(
        f"""
        <div class="trcc-card accent-blue">
            <div class="trcc-section-title">{signal_name.replace("_", " ").title()}</div>
            <div class="mini-label">What this may look like</div>
            <ul class="trcc-list">{looks_like}</ul>
            <div class="mini-label">How to respond</div>
            <ul class="trcc-list">{tam_response}</ul>
            <div class="mini-label">Questions to ask</div>
            <ul class="trcc-list">{questions}</ul>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_soc_card(number: int, title: str, body: str, details_title: str, details_items: list[str], accent: str = "orange") -> None:
    with st.container():
        st.markdown(
            f"""
            <div class="soc-card-shell accent-{accent}">
                <div class="soc-card-top">
                    <div class="number-badge">{number}</div>
                    <div class="soc-card-main">
                        <div class="numbered-title">{title}</div>
                        <div class="numbered-body">{body}</div>
                    </div>
                </div>
            """,
            unsafe_allow_html=True,
        )

        with st.expander(details_title):
            if details_items:
                for item in details_items:
                    st.markdown(f"- {item}")
            else:
                st.write("No additional detail is currently defined for this scenario.")

        st.markdown("</div>", unsafe_allow_html=True)


def render_timeline_dropdowns(timeline_data: list[dict]) -> None:
    for item in timeline_data:
        step_number = item.get("step_number", "")
        step_text = item.get("step_text", "")
        details = safe_list(item.get("details", []))

        st.markdown(
            f"""
            <div class="timeline-card-shell">
                <div class="timeline-card-top">
                    <div class="timeline-index">{step_number}</div>
                    <div class="timeline-card-main">
                        <div class="timeline-card-title">Attack Step {step_number}</div>
                        <div class="timeline-card-body">{step_text}</div>
                    </div>
                </div>
            """,
            unsafe_allow_html=True,
        )

        with st.expander("Open timeline explanation"):
            for detail in details:
                st.markdown(f"- {detail}")

        st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------
# CSS
# ---------------------------
st.markdown(
    """
    <style>
    :root {
        --bg: #07111a;
        --panel: #0d1822;
        --panel-2: #101b26;
        --border: #1a2b39;
        --border-soft: #243748;
        --text: #e8f0f7;
        --muted: #98a9b9;
        --muted-2: #bfd0de;
        --orange: #f97316;
        --orange-soft: rgba(249, 115, 22, 0.12);
        --green: #22c55e;
        --green-soft: rgba(34, 197, 94, 0.10);
        --blue: #7dd3fc;
        --blue-soft: rgba(125, 211, 252, 0.10);
        --shadow: 0 10px 28px rgba(0, 0, 0, 0.28);
    }

    html, body, [data-testid="stAppViewContainer"], .stApp {
        background:
            radial-gradient(circle at top right, rgba(249,115,22,0.06), transparent 22%),
            radial-gradient(circle at top left, rgba(125,211,252,0.05), transparent 20%),
            linear-gradient(180deg, #061019 0%, #07111a 100%);
        color: var(--text);
    }

    [data-testid="stHeader"] {
        background: transparent;
    }

    .block-container {
        max-width: 1600px;
        padding-top: 1rem;
        padding-bottom: 2rem;
    }

    p, li, div, label, span {
        color: var(--text);
    }

    .hero-shell {
        background: linear-gradient(180deg, rgba(18,33,48,0.96), rgba(10,20,29,0.96));
        border: 1px solid var(--border);
        border-radius: 20px;
        padding: 1.2rem 1.25rem 1.1rem 1.25rem;
        box-shadow: var(--shadow);
        margin-bottom: 1.2rem;
    }

    .hero-topline {
        display: inline-block;
        font-size: 0.72rem;
        letter-spacing: 0.11em;
        text-transform: uppercase;
        color: var(--muted);
        margin-bottom: 0.55rem;
    }

    .hero-title {
        font-size: 2.1rem;
        font-weight: 800;
        line-height: 1.05;
        color: var(--orange);
        margin: 0;
    }

    .hero-subtitle {
        margin-top: 0.45rem;
        color: var(--muted-2);
        font-size: 0.98rem;
        line-height: 1.5;
        max-width: 920px;
    }

    .chip-row {
        display: flex;
        flex-wrap: wrap;
        gap: 0.55rem;
        margin-top: 0.9rem;
    }

    .chip {
        display: inline-flex;
        align-items: center;
        padding: 0.42rem 0.72rem;
        border-radius: 999px;
        border: 1px solid var(--border-soft);
        background: rgba(255,255,255,0.02);
        color: var(--text);
        font-size: 0.82rem;
        font-weight: 600;
    }

    .chip-orange {
        border-color: rgba(249,115,22,0.35);
        background: var(--orange-soft);
        color: #ffd7c0;
    }

    .chip-green {
        border-color: rgba(34,197,94,0.35);
        background: var(--green-soft);
        color: #c8f6d8;
    }

    .chip-blue {
        border-color: rgba(125,211,252,0.35);
        background: var(--blue-soft);
        color: #d8f1ff;
    }

    [data-testid="stSelectbox"] {
        margin-bottom: 0.2rem;
    }

    [data-testid="stSelectbox"] label {
        color: #d8e3ec !important;
        font-size: 0.92rem !important;
        font-weight: 700 !important;
    }

    [data-testid="stSelectbox"] > div {
        border: 2px solid #f97316 !important;
        border-radius: 16px !important;
        padding: 4px !important;
        background: rgba(249,115,22,0.08) !important;
    }

    [data-testid="stSelectbox"] > div:hover {
        border: 2px solid #fb923c !important;
        background: rgba(249,115,22,0.12) !important;
    }

    [data-testid="stSelectbox"] > div > div {
        background: linear-gradient(180deg, #0d1822, #0a141d) !important;
        border: 1px solid var(--border-soft) !important;
        border-radius: 14px !important;
        min-height: 52px !important;
        box-shadow: none !important;
    }

    [data-testid="stSelectbox"] div[data-baseweb="select"] > div,
    [data-testid="stSelectbox"] input {
        color: #f2f7fb !important;
    }

    [role="listbox"], [role="option"], [data-baseweb="popover"] {
        background: #0d1822 !important;
        color: #f2f7fb !important;
    }

    [role="listbox"] {
        border: 1px solid var(--border-soft) !important;
    }

    [role="option"]:hover {
        background: #122130 !important;
    }

    .section-kicker {
        color: var(--orange);
        font-size: 0.8rem;
        letter-spacing: 0.07em;
        text-transform: uppercase;
        margin-bottom: 0.4rem;
        font-weight: 700;
    }

    .section-heading {
        color: var(--text);
        font-weight: 700;
        font-size: 1.12rem;
        margin-bottom: 0.15rem;
    }

    .section-sub {
        color: var(--muted);
        font-size: 0.92rem;
        margin-bottom: 1rem;
    }

    .metric-tile {
        background: linear-gradient(180deg, rgba(16,28,39,0.98), rgba(12,21,30,0.98));
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 1rem;
        box-shadow: var(--shadow);
        min-height: 150px;
        display: flex;
        flex-direction: column;
        justify-content: flex-start;
        margin-bottom: 0.85rem;
    }

    .metric-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--muted);
        margin-bottom: 0.55rem;
        font-weight: 700;
    }

    .metric-value {
        font-size: 0.98rem;
        line-height: 1.5;
        font-weight: 700;
        color: var(--text);
        display: -webkit-box;
        -webkit-line-clamp: 6;
        -webkit-box-orient: vertical;
        overflow: hidden;
    }

    .context-panel {
        background: linear-gradient(180deg, rgba(14,25,35,0.98), rgba(10,20,29,0.98));
        border: 1px solid var(--border);
        border-radius: 18px;
        padding: 1rem;
        box-shadow: var(--shadow);
        min-height: 170px;
        display: flex;
        flex-direction: column;
        margin-bottom: 1rem;
    }

    .context-title {
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--muted);
        margin-bottom: 0.7rem;
        font-weight: 800;
    }

    .context-body {
        color: var(--text);
        font-size: 1rem;
        line-height: 1.65;
        font-weight: 500;
    }

    .accent-orange .context-title,
    .accent-orange .trcc-section-title {
        color: var(--orange);
    }

    .accent-green .context-title,
    .accent-green .trcc-section-title {
        color: var(--green);
    }

    .accent-blue .context-title,
    .accent-blue .trcc-section-title {
        color: var(--blue);
    }

    .trcc-card {
        background: linear-gradient(180deg, rgba(15,26,36,0.98), rgba(10,20,29,0.98));
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 1rem 1rem 0.95rem 1rem;
        box-shadow: var(--shadow);
        min-height: 220px;
        margin-bottom: 1rem;
    }

    .trcc-section-title {
        font-size: 0.98rem;
        font-weight: 700;
        margin-bottom: 0.75rem;
    }

    .trcc-list {
        margin: 0;
        padding-left: 1.08rem;
    }

    .trcc-list li {
        margin-bottom: 0.66rem;
        color: #d9e4ec;
        line-height: 1.45;
    }

    .mini-label {
        color: var(--muted-2);
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-weight: 700;
        margin-top: 0.7rem;
        margin-bottom: 0.45rem;
    }

    .soc-card-shell,
    .timeline-card-shell {
        background: linear-gradient(180deg, rgba(15,26,36,0.98), rgba(10,20,29,0.98));
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 0.9rem;
        box-shadow: var(--shadow);
        margin-bottom: 1rem;
    }

    .soc-card-top,
    .timeline-card-top {
        display: grid;
        grid-template-columns: 42px 1fr;
        gap: 0.8rem;
        align-items: start;
        margin-bottom: 0.5rem;
    }

    .soc-card-main,
    .timeline-card-main {
        min-width: 0;
    }

    .number-badge,
    .timeline-index {
        width: 34px;
        height: 34px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 800;
        font-size: 0.95rem;
        background: var(--orange-soft);
        border: 1px solid rgba(249,115,22,0.35);
        color: var(--orange);
    }

    .accent-green .number-badge {
        background: var(--green-soft);
        border: 1px solid rgba(34,197,94,0.35);
        color: var(--green);
    }

    .accent-blue .number-badge {
        background: var(--blue-soft);
        border: 1px solid rgba(125,211,252,0.35);
        color: var(--blue);
    }

    .timeline-card-title,
    .numbered-title {
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--muted);
        font-weight: 700;
        margin-bottom: 0.45rem;
    }

    .timeline-card-body,
    .numbered-body {
        font-size: 0.97rem;
        line-height: 1.58;
        color: var(--text);
        font-weight: 500;
    }

    [data-testid="stExpander"] {
        border: none !important;
        background: transparent !important;
        box-shadow: none !important;
        margin-top: 0.2rem !important;
    }

    .streamlit-expanderHeader {
        font-size: 0.9rem !important;
        font-weight: 700 !important;
        color: #f2f7fb !important;
        border-top: 1px solid var(--border-soft);
        padding-top: 0.7rem !important;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 0.45rem;
        background: rgba(255,255,255,0.015);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 0.35rem;
        margin-top: 0.5rem;
        margin-bottom: 1rem;
    }

    .stTabs [data-baseweb="tab"] {
        background: transparent;
        border-radius: 10px;
        color: #9fb1bf;
        font-weight: 600;
        padding: 0.55rem 0.9rem;
        height: auto;
    }

    .stTabs [aria-selected="true"] {
        background: rgba(249,115,22,0.12) !important;
        color: #ffd6c0 !important;
    }

    @media (max-width: 1100px) {
        .metric-tile {
            min-height: 130px;
        }

        .context-panel {
            min-height: 150px;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------
# DATA
# ---------------------------
scenario_names = list(SCENARIOS.keys())

# ---------------------------
# HERO
# ---------------------------
st.markdown(
    """
    <div class="hero-shell">
        <div>
            <div class="hero-topline">Scenario-Driven Security Decision Support</div>
            <div class="hero-title">Threat &amp; Response Command Center</div>
            <div class="hero-subtitle">
                Structured incident review for investigation, response planning, customer communication,
                and TAM decision support during live security events.
            </div>
            <div class="chip-row">
                <div class="chip chip-orange">SOC Investigation</div>
                <div class="chip chip-green">Response Planning</div>
                <div class="chip chip-blue">Customer + TAM Guidance</div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------
# TOP CONTROL
# ---------------------------
top_left, top_right = st.columns([1.45, 1], gap="large")

with top_left:
    st.markdown(
        """
        <div class="section-kicker">Incident Control</div>
        <div class="section-heading">Scenario Workspace</div>
        <div class="section-sub">
            Choose a scenario to drive the investigation and response flow below.
        </div>
        """,
        unsafe_allow_html=True,
    )

with top_right:
    selected_name = st.selectbox("Select Scenario", scenario_names, index=0)

scenario = SCENARIOS[selected_name]
snapshot = safe_dict(scenario.get("incident_snapshot", {}))
actions = safe_dict(scenario.get("response_actions", {}))
guidance = safe_dict(scenario.get("customer_guidance", {}))
platform_value = safe_list(scenario.get("platform_value", []))
timeline_steps = safe_list(scenario.get("timeline", []))
customer_decisions = safe_dict(scenario.get("customer_decisions", {}))
validation_items = safe_list(scenario.get("validation_thinking", []))
signals = safe_dict(scenario.get("signals", {}))

risk_lens_body, risk_lens_details = build_risk_lens(snapshot, validation_items, signals)
timeline_data = build_timeline_explanations(snapshot, timeline_steps)

# ---------------------------
# SNAPSHOT
# ---------------------------
st.markdown(
    """
    <div class="section-kicker">Incident Context</div>
    <div class="section-heading">Command Snapshot</div>
    <div class="section-sub">
        Start with a clean read of what is happening, what it could mean, and where the team should focus first.
    </div>
    """,
    unsafe_allow_html=True,
)

m1, m2, m3 = st.columns(3, gap="medium")
with m1:
    render_metric_tile("Observed Activity", snapshot.get("observed_activity", "Not provided"), accent="orange")
with m2:
    render_metric_tile("Primary Concern", snapshot.get("initial_concern", "Not provided"), accent="blue")
with m3:
    render_metric_tile("Business Impact", snapshot.get("business_impact", "Not provided"), accent="green")

render_context_panel(
    "What the team is seeing",
    snapshot.get("team_context", snapshot.get("observed_activity", "Not provided")),
    accent="orange",
)

render_context_panel(
    "Likely attacker objective",
    snapshot.get("objective_context", snapshot.get("attacker_objective", "Not provided")),
    accent="green",
)

# ---------------------------
# TABS
# ---------------------------
tab_soc, tab_response, tab_customer, tab_tam, tab_platform, tab_timeline = st.tabs(
    [
        "SOC Investigation",
        "Response Actions",
        "Customer Guidance",
        "TAM Assist",
        "Platform Advantage",
        "Attack Timeline",
    ]
)

# ---------------------------
# SOC INVESTIGATION
# ---------------------------
with tab_soc:
    st.markdown(
        """
        <div class="section-kicker">Analyst Workflow</div>
        <div class="section-heading">SOC Investigation View</div>
        <div class="section-sub">
            Keep this view focused, and avoid repeating the same intent already shown above.
        </div>
        """,
        unsafe_allow_html=True,
    )

    signal_detail_items = []
    for category, items in signals.items():
        for item in safe_list(items):
            signal_detail_items.append(f"{category.replace('_', ' ').title()}: {item}")

    standout_items = [
        "The activity involves a privileged identity or high-value access path." if "privileged" in snapshot.get("team_context", "").lower() or "privileged" in snapshot.get("observed_activity", "").lower() else "",
        "The location, timing, or access pattern does not align with normal user behavior." if "unusual" in snapshot.get("team_context", "").lower() or "normal behavior" in snapshot.get("team_context", "").lower() or "foreign" in snapshot.get("observed_activity", "").lower() else "",
        "The signal may be using legitimate access paths, which can make a real intrusion look smaller at first." if "legitimate" in snapshot.get("team_context", "").lower() else "",
        "The main question is what happened after access was granted.",
    ]
    standout_items = [item for item in standout_items if item]

    left, right = st.columns(2, gap="large")

    with left:
        render_soc_card(
            1,
            "Detection Signal",
            snapshot.get("observed_activity", "No observed activity provided."),
            "Open signal detail",
            signal_detail_items,
            accent="orange",
        )

        render_soc_card(
            2,
            "Why This Stands Out",
            standout_items[0] if standout_items else "This signal deserves scrutiny because it may represent more than routine account noise.",
            "Open why this is notable",
            standout_items,
            accent="orange",
        )

    with right:
        render_soc_card(
            3,
            "What to Validate First",
            validation_items[0] if validation_items else "Validate whether the activity reflects attempted access, confirmed compromise, or environmental noise.",
            "Open validation questions",
            validation_items,
            accent="green",
        )

        render_soc_card(
            4,
            "Immediate Risk Lens",
            risk_lens_body,
            "Open risk context",
            risk_lens_details,
            accent="blue",
        )

# ---------------------------
# RESPONSE ACTIONS
# ---------------------------
with tab_response:
    st.markdown(
        """
        <div class="section-kicker">Action Layer</div>
        <div class="section-heading">Response Actions</div>
        <div class="section-sub">
            Prioritize what needs to happen now, next, and after stabilization.
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns(3, gap="large")

    with c1:
        render_list_card("Immediate", safe_list(actions.get("immediate", [])), accent="orange")
    with c2:
        render_list_card("Short-Term", safe_list(actions.get("short_term", [])), accent="green")
    with c3:
        render_list_card(
            "Preventive",
            safe_list(actions.get("preventive", [])) or safe_list(actions.get("long_term", [])),
            accent="blue",
        )

# ---------------------------
# CUSTOMER GUIDANCE
# ---------------------------
with tab_customer:
    st.markdown(
        """
        <div class="section-kicker">Communication Layer</div>
        <div class="section-heading">Customer Guidance</div>
        <div class="section-sub">
            Guide the customer toward clarity, ownership, and the next decision.
        </div>
        """,
        unsafe_allow_html=True,
    )

    left, right = st.columns(2, gap="large")

    with left:
        render_list_card(
            "What the customer needs to know right now",
            safe_list(customer_decisions.get("need_to_know", [])),
            accent="green",
        )
        render_list_card(
            "What they should validate internally",
            safe_list(customer_decisions.get("validate_internally", [])),
            accent="blue",
        )

    with right:
        render_list_card(
            "What decision they may need to make",
            safe_list(customer_decisions.get("decisions", [])),
            accent="orange",
        )
        render_list_card(
            "What they may be underestimating",
            safe_list(customer_decisions.get("underestimating", [])),
            accent="green",
        )

# ---------------------------
# TAM ASSIST
# ---------------------------
with tab_tam:
    st.markdown(
        """
        <div class="section-kicker">Behavior + Decision Support</div>
        <div class="section-heading">TAM Assist</div>
        <div class="section-sub">
            Use behavior cues to guide the room, reduce confusion, and keep the conversation productive.
        </div>
        """,
        unsafe_allow_html=True,
    )

    guidance_items = list(guidance.items())
    if guidance_items:
        for row_start in range(0, len(guidance_items), 2):
            cols = st.columns(2, gap="large")
            row_items = guidance_items[row_start:row_start + 2]
            for col, (signal_name, content) in zip(cols, row_items):
                with col:
                    render_guidance_block(signal_name, content)
    else:
        st.info("No TAM guidance is currently defined for this scenario.")

# ---------------------------
# PLATFORM ADVANTAGE
# ---------------------------
with tab_platform:
    st.markdown(
        """
        <div class="section-kicker">Operational Leverage</div>
        <div class="section-heading">Platform Advantage</div>
        <div class="section-sub">
            Modeled after modern security operations platforms like Palo Alto Cortex/XSIAM — focused on correlation, context, and faster decision-making.
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns(3, gap="large")

    with col1:
        render_list_card(
            "What a Correlated Platform Reveals",
            [
                "Identity, access, and behavioral signals tied into a single view",
                "Login events enriched with location, device, and activity context",
                "Ability to see what happened after access, not just the initial event",
                "Cross-domain visibility across identity, endpoint, cloud, and network where available",
            ],
            accent="green",
        )

    with col2:
        render_list_card(
            "How It Accelerates Investigation",
            [
                "Reduces the need to pivot across multiple tools",
                "Allows rapid validation of user intent versus compromise",
                "Speeds up triage by correlating signals automatically",
                "Moves investigation from alert to narrative faster",
            ],
            accent="orange",
        )

    with col3:
        render_list_card(
            "Where Traditional Tools Fall Short",
            [
                "Single alerts often lack behavioral context",
                "A successful login can be misread as low risk",
                "Post-authentication activity is frequently missed or underweighted",
                "Analysts spend time stitching evidence instead of making decisions",
            ],
            accent="blue",
        )

# ---------------------------
# TIMELINE
# ---------------------------
with tab_timeline:
    st.markdown(
        """
        <div class="section-kicker">Attack Progression</div>
        <div class="section-heading">Attack Timeline</div>
        <div class="section-sub">
            Expand each step to understand what that phase likely means and how the incident may be progressing.
        </div>
        """,
        unsafe_allow_html=True,
    )

    if timeline_data:
        render_timeline_dropdowns(timeline_data)
    else:
        st.info("No timeline steps are currently defined for this scenario.")
