import os
import sys
from pathlib import Path
import pandas as pd
import numpy as np
import streamlit as st
import matplotlib.pyplot as plt
import seaborn as sns
from PIL import Image

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from threatmoni.pipeline import ThreatMoniPipeline

st.set_page_config(
    page_title="ThreatMoni - OSINT Web Mining Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Professional Technical Styling
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #07111f 0%, #0e1728 48%, #111827 100%);
        color: #e5eef8;
    }
    [data-testid="stHeader"] {
        background: rgba(7, 17, 31, 0.85);
    }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0b1628 0%, #101b2d 100%);
        border-right: 1px solid #263957;
    }
    [data-testid="stSidebar"] .stRadio label {
        padding: 0.35rem 0.5rem;
        border-radius: 0.45rem;
    }
    [data-testid="stSidebar"] .stRadio label:hover {
        background: #19304b;
    }
    .hero {
        background: linear-gradient(120deg, rgba(14, 116, 144, .32), rgba(30, 64, 175, .28));
        border: 1px solid #28547a;
        border-radius: 18px;
        padding: 1.4rem 1.7rem;
        margin: 0.5rem 0 1.5rem;
        box-shadow: 0 14px 40px rgba(0, 0, 0, .22);
    }
    .hero-title {
        font-size: clamp(2rem, 4vw, 3.2rem);
        line-height: 1;
        font-weight: 800;
        letter-spacing: -0.05em;
        margin-bottom: 0.6rem;
    }
    .hero-subtitle {
        color: #a9c2da;
        font-size: 1rem;
    }
    .section-label {
        color: #67e8f9;
        font-size: .78rem;
        font-weight: 700;
        letter-spacing: .12em;
        text-transform: uppercase;
        margin-bottom: .35rem;
    }
    .metric-card {
        background: linear-gradient(145deg, #17253a, #111b2d);
        border: 1px solid #29415e;
        border-radius: 14px;
        padding: 1rem;
        min-height: 108px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, .16);
    }
    .metric-value {
        font-size: 28px;
        font-weight: bold;
        color: #67e8f9;
    }
    .metric-label {
        font-size: 11px;
        color: #9fb3c8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .status-pill {
        display: inline-block;
        border-radius: 999px;
        padding: .3rem .7rem;
        font-size: .76rem;
        font-weight: 700;
        background: #123b42;
        color: #67e8f9;
    }
    div[data-testid="stForm"] {
        background: rgba(17, 29, 48, .72);
        border: 1px solid #29415e;
        border-radius: 16px;
        padding: 1rem;
    }
    div[data-testid="stMetric"] {
        background: #17253a;
        border: 1px solid #29415e;
        padding: .85rem;
        border-radius: 12px;
    }
</style>
""", unsafe_allow_html=True)

def project_path(*parts: str) -> str:
    return str(PROJECT_ROOT.joinpath(*parts))


@st.cache_data
def load_pipeline_data():
    preds_path = project_path("outputs", "predictions", "threat_priority_predictions.csv")
    features_path = project_path("data", "processed", "threatmoni_features.csv")
    comp_path = project_path("outputs", "tables", "model_comparison.csv")
    
    df_preds = pd.read_csv(preds_path) if os.path.exists(preds_path) else pd.DataFrame()
    df_feats = pd.read_csv(features_path) if os.path.exists(features_path) else pd.DataFrame()
    df_comp = pd.read_csv(comp_path) if os.path.exists(comp_path) else pd.DataFrame()
    
    return df_preds, df_feats, df_comp


def append_threat(record: dict) -> None:
    raw_path = project_path("data", "raw", "cybersecurity_dataset.csv")
    dataset = pd.read_csv(raw_path)
    new_record = pd.DataFrame([record]).reindex(columns=dataset.columns)
    updated_dataset = pd.concat([dataset, new_record], ignore_index=True)
    updated_dataset.to_csv(raw_path, index=False)


def process_new_threat() -> pd.DataFrame:
    pipeline = ThreatMoniPipeline(
        raw_dir=project_path("data", "raw"),
        outputs_dir=project_path("outputs"),
    )
    scored, _ = pipeline.run()
    load_pipeline_data.clear()
    return scored


def output_path(*parts: str) -> str:
    return project_path("outputs", *parts)


def live_bar_chart(frame: pd.DataFrame, column: str, title: str, color: str = "#22d3ee") -> None:
    if frame.empty or column not in frame.columns:
        st.info(f"No {title.lower()} data available yet.")
        return
    counts = frame[column].fillna("Unknown").astype(str).value_counts().rename("Records")
    st.markdown(f"**{title}**")
    st.bar_chart(counts, color=color, height=260)


df_preds, df_feats, df_comp = load_pipeline_data()

# Header Banner
st.markdown(
    '<div class="hero"><div class="section-label">OSINT THREAT INTELLIGENCE PLATFORM</div>'
    '<div class="hero-title">🛡️ ThreatMoni</div>'
    '<div class="hero-subtitle">Detect, score, and prioritize emerging threats from every intelligence record.</div>'
    '</div>',
    unsafe_allow_html=True,
)

# Sidebar Controls
st.sidebar.header("🕹️ Framework Controls")
st.sidebar.markdown('<span class="status-pill">● LIVE DATASET</span>', unsafe_allow_html=True)
st.sidebar.caption(f"{len(df_preds):,} scored records loaded")
selected_tab = st.sidebar.radio(
    "Navigation",
    ["Add Threat", "Overview", "Threat Landscape", "Threat Priority", "Machine Learning", "Horizon Scanning", "Record Explorer", "Methodology"]
)

if selected_tab != "Add Threat" and df_preds.empty:
    st.error("Pipeline output not found. Please run `python run_pipeline.py` first.")
    st.stop()

# -----------------------------------------------------------------------------
# A. ADD THREAT
# -----------------------------------------------------------------------------
if selected_tab == "Add Threat":
    st.subheader("➕ Add a Threat Intelligence Record")
    st.caption("Submit a new OSINT record to score it and display the result in the dashboard.")

    existing_categories = (
        sorted(df_preds["Threat Category"].dropna().astype(str).unique().tolist())
        if "Threat Category" in df_preds.columns else ["DDoS", "Malware", "Phishing", "Ransomware"]
    )
    existing_actors = (
        sorted(df_preds["Threat Actor"].dropna().astype(str).unique().tolist())
        if "Threat Actor" in df_preds.columns else ["Unknown"]
    )
    existing_vectors = (
        sorted(df_preds["Attack Vector"].dropna().astype(str).unique().tolist())
        if "Attack Vector" in df_preds.columns else ["Network", "Email", "Web"]
    )
    existing_locations = (
        sorted(df_preds["Geographical Location"].dropna().astype(str).unique().tolist())
        if "Geographical Location" in df_preds.columns else ["Unknown"]
    )

    with st.form("add_threat_form", clear_on_submit=False):
        st.markdown("#### Record details")
        col1, col2 = st.columns(2)
        with col1:
            threat_category = st.selectbox("Threat Category", existing_categories)
            threat_actor = st.text_input("Threat Actor", value="Unknown")
            attack_vector = st.selectbox("Attack Vector", existing_vectors)
            location = st.selectbox("Geographical Location", existing_locations)
            iocs = st.text_input("IOCs (Indicators of Compromise)", placeholder="['192.0.2.10', 'CVE-2026-1234']")
            description = st.text_area("Threat Description", placeholder="Describe the observed threat activity.")
            keywords = st.text_input("Keyword Extraction", value="[]")
        with col2:
            sentiment = st.slider("Sentiment in Forums", 0.0, 1.0, 0.5, 0.01)
            severity = st.slider("Severity Score", 1, 5, 3)
            predicted_category = st.text_input("Predicted Threat Category", value=threat_category)
            defense = st.text_input("Suggested Defense Mechanism", value="Investigate and contain")
            risk_level = st.slider("Risk Level Prediction", 1, 5, 3)
            entities = st.text_input("Named Entities (NER)", value="[]")
            topic = st.text_input("Topic Modeling Labels", value=threat_category)

        submitted = st.form_submit_button("⚡ Process Threat", type="primary", use_container_width=True)

    if submitted:
        if not description.strip():
            st.error("Threat description is required.")
        else:
            record = {
                "Threat Category": threat_category,
                "IOCs (Indicators of Compromise)": iocs.strip() or "[]",
                "Threat Actor": threat_actor.strip() or "Unknown",
                "Attack Vector": attack_vector,
                "Geographical Location": location,
                "Sentiment in Forums": sentiment,
                "Severity Score": severity,
                "Predicted Threat Category": predicted_category.strip() or threat_category,
                "Suggested Defense Mechanism": defense.strip() or "Investigate and contain",
                "Risk Level Prediction": risk_level,
                "Cleaned Threat Description": description.strip(),
                "Keyword Extraction": keywords.strip() or "[]",
                "Named Entities (NER)": entities.strip() or "[]",
                "Topic Modeling Labels": topic.strip() or threat_category,
                "Word Count": len(description.split()),
            }
            try:
                append_threat(record)
                scored = process_new_threat()
                new_result = scored.iloc[[-1]]
                st.success("Threat added and processed successfully.")
                st.markdown("### New Threat Output")
                result_metrics = st.columns(4)
                result_values = [
                    ("TPI score", new_result["tpi_score"].iloc[0], ""),
                    ("Priority", new_result["threat_priority"].iloc[0], ""),
                    ("Severity", new_result["Severity Score"].iloc[0], "/ 5"),
                    ("Risk level", new_result["Risk Level Prediction"].iloc[0], "/ 5"),
                ]
                for metric_col, (label, value, suffix) in zip(result_metrics, result_values):
                    with metric_col:
                        st.metric(label, f"{value}{suffix}")
                result_cols = [
                    "Threat Category", "Threat Actor", "Attack Vector",
                    "tpi_score", "threat_priority", "scs_score", "iq_score",
                    "trs_score", "Cleaned Threat Description",
                ]
                st.dataframe(new_result[[c for c in result_cols if c in new_result.columns]], use_container_width=True)
                st.info("The new record is now available in Threat Priority and Record Explorer.")
            except (OSError, ValueError, KeyError, RuntimeError) as exc:
                st.error(f"Could not process the new threat: {exc}")

# -----------------------------------------------------------------------------
# B. OVERVIEW
# -----------------------------------------------------------------------------
elif selected_tab == "Overview":
    st.markdown('<div class="section-label">COMMAND CENTER</div>', unsafe_allow_html=True)
    st.subheader("📊 Executive Threat Horizon Overview")
    st.caption("A live view of all scored intelligence records and their current risk posture.")
    
    total_records = len(df_preds)
    unique_threats = df_preds["Threat Category"].nunique() if "Threat Category" in df_preds.columns else 0
    unique_cves = int(df_preds["cve_count"].sum()) if "cve_count" in df_preds.columns else 0
    unique_iocs = int(df_preds["ioc_count"].sum()) if "ioc_count" in df_preds.columns else 0
    high_count = int((df_preds["threat_priority"] == "High").sum())
    critical_count = int((df_preds["threat_priority"] == "Critical").sum())

    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1:
        st.markdown(f'<div class="metric-card"><div class="metric-value">{total_records}</div><div class="metric-label">Total Ingested</div></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="metric-card"><div class="metric-value">{unique_threats}</div><div class="metric-label">Threat Classes</div></div>', unsafe_allow_html=True)
    with col3:
        st.markdown(f'<div class="metric-card"><div class="metric-value">{unique_cves}</div><div class="metric-label">Extracted CVEs</div></div>', unsafe_allow_html=True)
    with col4:
        st.markdown(f'<div class="metric-card"><div class="metric-value">{unique_iocs}</div><div class="metric-label">Total IOCs</div></div>', unsafe_allow_html=True)
    with col5:
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #e67e22;">{high_count}</div><div class="metric-label">High Priority</div></div>', unsafe_allow_html=True)
    with col6:
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #e74c3c;">{critical_count}</div><div class="metric-label">Critical Priority</div></div>', unsafe_allow_html=True)

    st.markdown("### Live Threat Signals")
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        live_bar_chart(df_preds, "threat_priority", "Priority distribution", "#38bdf8")
    with chart_col2:
        live_bar_chart(df_preds, "Threat Category", "Threat categories", "#a78bfa")

    st.markdown("### Key Horizon Figures")
    fig_col1, fig_col2 = st.columns(2)
    with fig_col1:
        priority_path = output_path("figures", "threat_priority_distribution.png")
        if os.path.exists(priority_path):
            st.image(priority_path, caption="Threat Priority Distribution (TPI Level)", use_container_width=True)
    with fig_col2:
        tpi_path = output_path("figures", "tpi_distribution.png")
        if os.path.exists(tpi_path):
            st.image(tpi_path, caption="Continuous TPI Score Distribution", use_container_width=True)

# -----------------------------------------------------------------------------
# C. THREAT LANDSCAPE
# -----------------------------------------------------------------------------
elif selected_tab == "Threat Landscape":
    st.markdown('<div class="section-label">INTELLIGENCE MAP</div>', unsafe_allow_html=True)
    st.subheader("🌐 OSINT Threat Landscape Analysis")
    st.caption("Explore how categories, attack vectors, and locations are distributed across the live dataset.")
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        live_bar_chart(df_preds, "Attack Vector", "Attack vectors", "#34d399")
    with chart_col2:
        live_bar_chart(df_preds, "Geographical Location", "Geographical locations", "#f59e0b")

    col1, col2 = st.columns(2)
    with col1:
        class_distribution = output_path("figures", "class_distribution.png")
        if os.path.exists(class_distribution):
            st.image(class_distribution, caption="Ground-Truth Category Distribution", use_container_width=True)
    with col2:
        category_distribution = output_path("figures", "threat_category_distribution.png")
        if os.path.exists(category_distribution):
            st.image(category_distribution, caption="Category Share", use_container_width=True)

    st.markdown("### Attack Vectors & Geographic Intelligence")
    col3, col4 = st.columns(2)
    with col3:
        attack_vector_frequency = output_path("figures", "attack_vector_frequency.png")
        if os.path.exists(attack_vector_frequency):
            st.image(attack_vector_frequency, caption="Attack Vectors", use_container_width=True)
    with col4:
        geographical_distribution = output_path("figures", "geographical_distribution.png")
        if os.path.exists(geographical_distribution):
            st.image(geographical_distribution, caption="Geographical Distribution", use_container_width=True)

# -----------------------------------------------------------------------------
# D. THREAT PRIORITY
# -----------------------------------------------------------------------------
elif selected_tab == "Threat Priority":
    st.markdown('<div class="section-label">RISK OPERATIONS</div>', unsafe_allow_html=True)
    st.subheader("🎯 Threat Priority Index (TPI) Breakdown")
    st.caption("Records are ranked by the calculated Threat Priority Index.")
    st.markdown("### Top Critical Priority OSINT Records")
    high_critical = df_preds[df_preds["threat_priority"].isin(["High", "Critical"])].sort_values(by="tpi_score", ascending=False)
    if high_critical.empty:
        st.info("No high or critical priority records are currently available.")
    else:
        st.dataframe(high_critical[["Threat Category", "Threat Actor", "Attack Vector", "tpi_score", "threat_priority", "Cleaned Threat Description"]].head(15), use_container_width=True, hide_index=True)

    severity_tpi = output_path("figures", "severity_vs_tpi.png")
    if os.path.exists(severity_tpi):
        st.image(severity_tpi, caption="Calculated TPI Score vs Raw Severity Rating", use_container_width=True)

# -----------------------------------------------------------------------------
# E. MACHINE LEARNING
# -----------------------------------------------------------------------------
elif selected_tab == "Machine Learning":
    st.markdown('<div class="section-label">MODEL BENCHMARKS</div>', unsafe_allow_html=True)
    st.subheader("🤖 Supervised Machine Learning Benchmark")
    st.markdown("Target Variable: **Threat Category** (DDoS, Malware, Phishing, Ransomware)")
    
    if not df_comp.empty:
        st.table(df_comp)
    
    col1, col2 = st.columns(2)
    with col1:
        model_f1 = output_path("figures", "model_f1.png")
        if os.path.exists(model_f1):
            st.image(model_f1, caption="Model Comparison (Weighted F1 Score)", use_container_width=True)
    with col2:
        confusion_matrix = output_path("figures", "confusion_matrix_random_forest.png")
        if os.path.exists(confusion_matrix):
            st.image(confusion_matrix, caption="Confusion Matrix - Random Forest", use_container_width=True)

    feature_importance = output_path("figures", "feature_importance_random_forest.png")
    if os.path.exists(feature_importance):
        st.image(feature_importance, caption="Top 10 Feature Importances (Random Forest)", use_container_width=True)

# -----------------------------------------------------------------------------
# F. HORIZON SCANNING
# -----------------------------------------------------------------------------
elif selected_tab == "Horizon Scanning":
    st.markdown('<div class="section-label">EMERGING SIGNALS</div>', unsafe_allow_html=True)
    st.subheader("🔭 OSINT Threat Horizon Scanning & Emerging Indicators")
    
    top_threats_path = output_path("tables", "top_threats.csv")
    if os.path.exists(top_threats_path):
        st.markdown("### Threat Categories Ranked by Horizon Priority (Mean TPI)")
        st.dataframe(pd.read_csv(top_threats_path), use_container_width=True)

    emerging_threats = output_path("figures", "emerging_threats.png")
    if os.path.exists(emerging_threats):
        st.image(emerging_threats, caption="Emerging Threat Priority Spectrum", use_container_width=True)

# -----------------------------------------------------------------------------
# G. RECORD EXPLORER
# -----------------------------------------------------------------------------
elif selected_tab == "Record Explorer":
    st.markdown('<div class="section-label">SEARCH & FILTER</div>', unsafe_allow_html=True)
    st.subheader("🔍 Interactive OSINT Record Explorer")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        prio_filter = st.multiselect("Filter by Threat Priority", options=["Low", "Medium", "High", "Critical"], default=["High", "Critical"])
    with col2:
        cat_filter = st.multiselect("Filter by Threat Category", options=df_preds["Threat Category"].unique().tolist(), default=df_preds["Threat Category"].unique().tolist())
    with col3:
        min_tpi, max_tpi = st.slider("TPI Score Range", 0.0, 100.0, (0.0, 100.0))

    filtered_df = df_preds[
        (df_preds["threat_priority"].isin(prio_filter)) &
        (df_preds["Threat Category"].isin(cat_filter)) &
        (df_preds["tpi_score"] >= min_tpi) &
        (df_preds["tpi_score"] <= max_tpi)
    ]
    
    st.markdown(f"Displaying **{len(filtered_df):,}** matching OSINT records.")
    st.dataframe(filtered_df[["Threat Category", "Threat Actor", "Attack Vector", "Geographical Location", "tpi_score", "threat_priority", "Cleaned Threat Description"]], use_container_width=True, hide_index=True)

# -----------------------------------------------------------------------------
# H. METHODOLOGY
# -----------------------------------------------------------------------------
elif selected_tab == "Methodology":
    st.subheader("📐 ThreatMoni Conceptual Source Methodology & Formulas")
    
    st.markdown("""
    ### Formulations & Scoring System
    
    1. **Source Credibility Score (SCS):**
       $$SCS = \\frac{R + U + C + A}{4}$$
       *Where R = Reliability, U = Update Frequency/Detail, C = Consistency, A = Authority.*
       
    2. **Threat Frequency Score (TFS):**
       $$TFS = \\frac{N_t}{N}$$
       *Where $N_t$ = occurrences of threat category, $N$ = total collected threat records.*
       
    3. **Intelligence Quality (IQ):**
       $$IQ = 0.4(Completeness) + 0.3(IOC\\ Presence) + 0.3(Text\\ Granularity)$$
       
    4. **Threat Confidence Score (TCS):**
       $$TCS = \\alpha(SCS) + \\beta(IQ)$$
       *Default configured weights: $\\alpha = 0.5$, $\\beta = 0.5$.*
       
    5. **Threat Risk Score (TRS):**
       $$TRS = \\sum (W_i \\times F_i)$$
       *Weighted combination of severity rating, TFS, risk prediction, IOC density, and forum sentiment.*
       
    6. **Threat Priority Index (TPI):**
       $$TPI = \\frac{TRS \\times TCS}{100}$$
       
    #### Priority Threshold Mapping:
    - **0 – 25:** Low Priority
    - **26 – 50:** Medium Priority
    - **51 – 75:** High Priority
    - **76 – 100:** Critical Priority
    """)
