# Algorithm 1: ThreatMoni — Multi-Source Threat Monitoring and Intelligence Algorithm

```text
Algorithm 1. ThreatMoni — Multi-Source Threat Monitoring and Intelligence Algorithm
--------------------------------------------------------------------------------
Input:  Multiple OSINT sources S = {s1, s2, ..., sn}
Output: Prioritized Threat Intelligence TI, Risk Assessment RA,
        Threat Forecast TF, and Alerts A
Begin
  Step 1:  Initialize source list, collection mechanisms, preprocessing
           configuration, feature definitions, models, knowledge base,
           and threshold parameters.
  Step 2:  Collect OSINT data via web crawling, API collection, RSS
           parsing, web scraping, HTML parsing, and metadata extraction.
  Step 3:  Validate collected records; remove inaccessible, empty,
           corrupted, or irrelevant entries.
  Step 4:  Preprocess data — remove duplicates, handle missing values,
           filter noise, normalize text, tokenize, and validate formats.
  Step 5:  Assess source credibility and calculate the Source
           Credibility Score (SCS) for each observation, Eq. (1).
  Step 6:  Extract threat entities and IOCs using NLP and
           cybersecurity-specific extraction techniques.
  Step 7:  Correlate extracted entities and observations across
           sources to identify shared threats, campaigns, or behaviors.
  Step 8:  Perform temporal correlation to determine whether threat
           activity is increasing, decreasing, or stable.
  Step 9:  Update the Threat Knowledge Base with validated entities,
           relationships, and temporal data.
  Step 10: Perform feature engineering — generate Threat Frequency,
           Severity, Source Reliability, Attack Category, Confidence,
           Geographic, and Temporal features.
  Step 11: Calculate Threat Frequency Score (TFS), Eq. (2).
  Step 12: Calculate Threat Confidence (TC) from SCS, TFS, and
           supporting evidence, Eq. (3).
  Step 13: Calculate Threat Risk Score (TRS) from frequency, severity,
           confidence, reliability, and temporal activity, Eq. (4).
  Step 14: Apply machine learning models appropriate to the task
           (classification, anomaly detection, NLP, temporal prediction).
  Step 15: Detect emerging threats from unusual activity, increasing
           frequency, or strong multi-source evidence.
  Step 16: Perform threat forecasting using temporal observations and
           predictive models.
  Step 17: Calculate Threat Priority Index (TPI) from TRS and TC,
           Eq. (5).
  Step 18: Generate alerts for threats exceeding defined risk
           thresholds.
  Step 19: Generate visualization dashboards and decision-support
           reports.
  Step 20: Apply analyst feedback to refine monitoring, correlation,
           and scoring.
  Step 21: Repeat monitoring as new OSINT information becomes
           available.
End
--------------------------------------------------------------------------------
```

## Step-by-Step Mapping in Implementation

| Algorithm Step | Operational Module | Function / Responsibility |
| :--- | :--- | :--- |
| **Step 1–3** | `src/threatmoni/data_loader.py`, `profiler.py` | Feed discovery, input validation, row filtering |
| **Step 4** | `src/threatmoni/preprocessing.py` | Indicator-preserving text cleaning & deduplication |
| **Step 5** | `src/threatmoni/threat_scoring.py` | Compute Source Credibility Score (SCS) |
| **Step 6–9** | `src/threatmoni/nlp_engine.py`, `entity_extraction.py` | Regex & NLP indicator extraction, entity mapping |
| **Step 10–13** | `src/threatmoni/feature_engineering.py`, `threat_scoring.py` | TFS, IQ, TCS, and TRS calculations |
| **Step 14–16** | `src/threatmoni/model_training.py`, `horizon_scanning.py` | 6 ML classifiers & emerging threat trend analysis |
| **Step 17** | `src/threatmoni/threat_scoring.py` | Threat Priority Index (TPI) score calculation |
| **Step 18–19** | `src/threatmoni/reporting.py`, `app/streamlit_app.py` | Priority alert generation & interactive dashboard |
| **Step 20–21** | `src/threatmoni/pipeline.py` | Feedback loop & automated pipeline re-execution |
