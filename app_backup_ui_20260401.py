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
def render_info_card(title: str, body: str, accent: str = "orange") -> None:
    st.markdown(
        f"""
        <div class="trcc-card trcc-info-card accent-{accent}">
            <div class="trcc-card-label">{title}</div>
            <div class="trcc-card-body">{body}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_list_card(title: str, items: list[str], accent: str = "green") -> None:
    bullets = "".join(f"<li>{item}</li>" for item in items)
    st.markdown(
        f"""
        <div class="trcc-card trcc-list-card accent-{accent}">
            <div class="trcc-section-title">{title}</div>
            <ul class="trcc-list">
                {bullets}
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_timeline_card(steps: list[str]) -> None:
    blocks = "".join(
        f"""
        <div class="timeline-step">
            <div class="timeline-index">{idx}</div>
            <div class="timeline-text">{step}</div>
        </div>
        """
        for idx, step in enumerate(steps, 1)
    )
    st.markdown(
        f"""
        <div class="trcc-card">
            <div class="trcc-section-title">Incident Progression</div>
            <div class="timeline-wrap">
                {blocks}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_guidance_block(bias_name: str, content: dict) -> None:
    looks_like = "".join(
        f"<li>{item}</li>" for item in content.get("what_it_looks_like", [])
    )
    tam_response = "".join(
        f"<li>{item}</li>" for item in content.get("tam_response", [])
    )
    questions = "".join(
        f"<li>{item}</li>" for item in content.get("questions_to_ask", [])
    )

    st.markdown(
        f"""
        <div class="trcc-card accent-green">
            <div class="trcc-section-title">{bias_name.replace("_", " ").title()}</div>

            <div class="guidance-block-title">What it looks like</div>
            <ul class="trcc-list">{looks_like}</ul>

            <div class="guidance-block-title">What to say</div>
            <ul class="trcc-list">{tam_response}</ul>

            <div class="guidance-block-title">Questions to ask</div>
            <ul class="trcc-list">{questions}</ul>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------
# CSS
# ---------------------------
st.markdown(
    """
    <style>
    :root {
        --bg: #07111a;
        --panel: #0d1822;
        --panel-2: #0a141d;
        --panel-3: #122130;
        --border: #1a2b39;
        --border-soft: #23384a;
        --text: #e8f0f7;
        --muted: #96a8b8;
        --orange: #f97316;
        --orange-soft: rgba(249, 115, 22, 0.14);
        --green: #22c55e;
        --green-soft: rgba(34, 197, 94, 0.12);
        --shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
    }

    html, body, [data-testid="stAppViewContainer"], .stApp {
        background:
            radial-gradient(circle at top right, rgba(249, 115, 22, 0.08), transparent 22%),
            radial-gradient(circle at top left, rgba(34, 197, 94, 0.07), transparent 20%),
            linear-gradient(180deg, #061019 0%, #07111a 100%);
        color: var(--text);
    }

    [data-testid="stHeader"] {
        background: transparent;
    }

    .block-container {
        padding-top: 1.15rem;
        padding-bottom: 2rem;
        max-width: 1500px;
    }

    p, li, div, label, span {
        color: var(--text);
    }

    /* Hero */
    .hero-shell {
        background: linear-gradient(180deg, rgba(18,33,48,0.96), rgba(10,20,29,0.96));
        border: 1px solid var(--border);
        border-radius: 18px;
        padding: 1.2rem 1.25rem 1rem 1.25rem;
        box-shadow: var(--shadow);
        margin-bottom: 1rem;
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
        color: #b7c8d7;
        font-size: 0.98rem;
        line-height: 1.5;
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
        gap: 0.35rem;
        padding: 0.42rem 0.7rem;
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

    /* Selectbox */
    [data-testid="stSelectbox"] label {
        color: #b8c6d4 !important;
        font-size: 0.84rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.02em;
    }

    [data-testid="stSelectbox"] > div > div {
        background: linear-gradient(180deg, #0d1822, #0a141d) !important;
        border: 1px solid var(--border-soft) !important;
        border-radius: 12px !important;
        min-height: 48px !important;
        box-shadow: none !important;
    }

    [data-testid="stSelectbox"] div[data-baseweb="select"] > div {
        background: transparent !important;
        color: var(--text) !important;
    }

    /* Section headings */
    .section-kicker {
        color: var(--orange);
        font-size: 0.82rem;
        letter-spacing: 0.07em;
        text-transform: uppercase;
        margin-bottom: 0.45rem;
        font-weight: 700;
    }

    .section-heading {
        color: var(--text);
        font-weight: 700;
        font-size: 1.15rem;
        margin-bottom: 0.15rem;
    }

    .section-sub {
        color: var(--muted);
        font-size: 0.92rem;
        margin-bottom: 0.9rem;
    }

    /* Cards */
    .trcc-card {
        background: linear-gradient(180deg, rgba(15,26,36,0.98), rgba(10,20,29,0.98));
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 1rem 1rem 0.95rem 1rem;
        box-shadow: var(--shadow);
        height: 100%;
    }

    .trcc-info-card {
        min-height: 138px;
    }

    .trcc-list-card {
        min-height: 230px;
    }

    .trcc-card-label {
        font-size: 0.77rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--muted);
        margin-bottom: 0.5rem;
        font-weight: 700;
    }

    .trcc-card-body {
        color: var(--text);
        font-size: 1rem;
        line-height: 1.55;
        font-weight: 500;
    }

    .trcc-section-title {
        font-size: 0.98rem;
        font-weight: 700;
        margin-bottom: 0.8rem;
        color: var(--green);
    }

    .accent-orange .trcc-section-title,
    .accent-orange .trcc-card-label {
        color: var(--orange);
    }

    .accent-green .trcc-section-title,
    .accent-green .trcc-card-label {
        color: var(--green);
    }

    .trcc-list {
        margin: 0;
        padding-left: 1.1rem;
    }

    .trcc-list li {
        margin-bottom: 0.72rem;
        color: #d9e4ec;
        line-height: 1.48;
    }

    .guidance-block-title {
        color: #b7c8d7;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-weight: 700;
        margin-top: 0.7rem;
        margin-bottom: 0.5rem;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.45rem;
        background: rgba(255,255,255,0.015);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 0.35rem;
        margin-top: 0.35rem;
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

    /* Timeline */
    .timeline-wrap {
        display: flex;
        flex-direction: column;
        gap: 0.8rem;
        margin-top: 0.2rem;
    }

    .timeline-step {
        display: grid;
        grid-template-columns: 44px 1fr;
        gap: 0.8rem;
        align-items: start;
        background: rgba(255,255,255,0.02);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 0.8rem;
    }

    .timeline-index {
        width: 36px;
        height: 36px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: var(--orange-soft);
        border: 1px solid rgba(249,115,22,0.35);
        color: var(--orange);
        font-weight: 800;
    }

    .timeline-text {
        color: var(--text);
        line-height: 1.5;
        padding-top: 0.15rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------
# DATA
# ---------------------------
scenario_names = list(SCENARIOS.keys())
selected_name = scenario_names[0]

# ---------------------------
# HEADER / HERO
# ---------------------------
left, right = st.columns([4.4, 1.8], vertical_alignment="center")

with left:
    st.markdown(
        """
        <div class="hero-shell">
            <div class="hero-topline">Palo Alto–Focused Incident Guidance</div>
            <div class="hero-title">Threat &amp; Response Command Center</div>
            <div class="hero-subtitle">
                Structured investigation flow for signals, validation, response actions,
                platform context, and customer communication during live security events.
            </div>
            <div class="chip-row">
                <div class="chip chip-orange">Threat Review</div>
                <div class="chip chip-green">Cortex-Aligned</div>
                <div class="chip">TAM Decision Support</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with right:
    selected_name = st.selectbox("Scenario", scenario_names, index=0)

scenario = SCENARIOS[selected_name]
snapshot = scenario["incident_snapshot"]

# ---------------------------
# INCIDENT SNAPSHOT
# ---------------------------
st.markdown(
    """
    <div class="section-kicker">Incident Context</div>
    <div class="section-heading">Incident Snapshot</div>
    <div class="section-sub">
        Start with a clean read of what is happening, why it matters, and what it could lead to.
    </div>
    """,
    unsafe_allow_html=True,
)

snap_col1, snap_col2, snap_col3, snap_col4 = st.columns(4)

with snap_col1:
    render_info_card("Observed Activity", snapshot["observed_activity"], accent="orange")

with snap_col2:
    render_info_card("Initial Concern", snapshot["initial_concern"], accent="orange")

with snap_col3:
    render_info_card("Attacker Objective", snapshot["attacker_objective"], accent="green")

with snap_col4:
    render_info_card("Business Impact", snapshot["business_impact"], accent="green")

# ---------------------------
# TABS
# ---------------------------
tab_signals, tab_validation, tab_response, tab_guidance, tab_platform, tab_timeline = st.tabs(
    [
        "Signals",
        "Validation Thinking",
        "Response Actions",
        "Customer Guidance",
        "Platform Value",
        "Timeline",
    ]
)

# ---------------------------
# SIGNALS
# ---------------------------
with tab_signals:
    st.markdown(
        """
        <div class="section-kicker">Detection Context</div>
        <div class="section-heading">Signals Across the Environment</div>
        <div class="section-sub">
            Review what the environment is surfacing across identity, endpoint, network, cloud, and Palo Alto telemetry.
        </div>
        """,
        unsafe_allow_html=True,
    )

    signals = scenario["signals"]
    categories = list(signals.items())

    for row_start in range(0, len(categories), 3):
        cols = st.columns(3)
        row_items = categories[row_start:row_start + 3]

        for col, (category, items) in zip(cols, row_items):
            with col:
                render_list_card(category.replace("_", " ").title(), items, accent="green")

# ---------------------------
# VALIDATION THINKING
# ---------------------------
with tab_validation:
    st.markdown(
        """
        <div class="section-kicker">Analyst Discipline</div>
        <div class="section-heading">Validation Thinking</div>
        <div class="section-sub">
            Use structured questions to separate attempted activity from confirmed risk and avoid premature escalation.
        </div>
        """,
        unsafe_allow_html=True,
    )

    validation_items = scenario["validation_thinking"]
    rows = [
        validation_items[i:i + 2] for i in range(0, len(validation_items), 2)
    ]

    number = 1
    for row in rows:
        cols = st.columns(2)
        for col, item in zip(cols, row):
            with col:
                render_info_card(f"Validation Question {number}", item, accent="orange")
                number += 1

# ---------------------------
# RESPONSE ACTIONS
# ---------------------------
with tab_response:
    st.markdown(
        """
        <div class="section-kicker">Action Layer</div>
        <div class="section-heading">Response Actions</div>
        <div class="section-sub">
            Prioritize actions by time horizon so the team can move from immediate containment to longer-term hardening.
        </div>
        """,
        unsafe_allow_html=True,
    )

    actions = scenario["response_actions"]
    col1, col2, col3 = st.columns(3)

    with col1:
        render_list_card("Immediate", actions.get("immediate", []), accent="orange")

    with col2:
        render_list_card("Short-Term", actions.get("short_term", []), accent="green")

    with col3:
        render_list_card("Preventive", actions.get("preventive", []), accent="green")

# ---------------------------
# CUSTOMER GUIDANCE
# ---------------------------
with tab_guidance:
    st.markdown(
        """
        <div class="section-kicker">Communication Layer</div>
        <div class="section-heading">Customer Guidance</div>
        <div class="section-sub">
            Pair the technical situation with customer behavior cues so the TAM can guide the room, reduce panic, and keep decisions grounded.
        </div>
        """,
        unsafe_allow_html=True,
    )

    guidance_items = list(scenario["customer_guidance"].items())

    for row_start in range(0, len(guidance_items), 2):
        cols = st.columns(2)
        row_items = guidance_items[row_start:row_start + 2]

        for col, (bias_name, content) in zip(cols, row_items):
            with col:
                render_guidance_block(bias_name, content)

# ---------------------------
# PLATFORM VALUE
# ---------------------------
with tab_platform:
    st.markdown(
        """
        <div class="section-kicker">Platform Relevance</div>
        <div class="section-heading">Platform Value</div>
        <div class="section-sub">
            Tie the incident back to what Palo Alto surfaced, correlated, or made easier to validate in the customer environment.
        </div>
        """,
        unsafe_allow_html=True,
    )

    render_list_card("Why the Platform Matters Here", scenario["platform_value"], accent="green")

# ---------------------------
# TIMELINE
# ---------------------------
with tab_timeline:
    st.markdown(
        """
        <div class="section-kicker">Sequence of Events</div>
        <div class="section-heading">Timeline</div>
        <div class="section-sub">
            Walk the incident in order so the customer and internal team can align on progression, checkpoints, and current state.
        </div>
        """,
        unsafe_allow_html=True,
    )

    render_timeline_card(scenario["timeline"])
