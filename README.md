<p align="center">
  <img src="assets/logo.png" alt="ThreatMoni Logo" width="380"/>
</p>

<h1 align="center">ThreatMoni</h1>
<h3 align="center">OSINT Web Mining Framework for Threat Horizon Scanning</h3>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

ThreatMoni is a cybersecurity research framework designed to collect, preprocess, score, and analyze open-source threat intelligence (OSINT) from heterogeneous data feeds. The framework combines indicator-preserving text preprocessing, natural language threat entity extraction, multi-factor risk scoring, machine learning classification, and visual threat horizon scanning to transform unstructured threat feeds into actionable, prioritized security intelligence.

---

## Why ThreatMoni?

Modern Open-Source Intelligence (OSINT) feeds are highly fragmented, noisy, and unstandardized. Security operations centers (SOCs) and threat research teams face critical operational challenges:

- **Data Heterogeneity:** OSINT reports combine informal community descriptions, technical indicators (`CVE-*`, IP addresses, file hashes), and unstructured web text.
- **Preprocessing Granularity:** Standard NLP pipelines often strip or alter critical technical indicators like CVE identifiers or MITRE ATT&CK IDs.
- **Intelligence Prioritization:** Raw threat feeds lack standardized risk scoring, making it difficult to distinguish low-level background noise from high-severity emerging threat campaigns.

ThreatMoni addresses these challenges by establishing an end-to-end processing pipeline that preserves technical security indicators, computes mathematical Threat Priority Index (TPI) scores, and classifies threat vectors using benchmarked machine learning models.

---

## Add Threats from the Dashboard

The Streamlit dashboard supports dynamic threat ingestion:

1. Start the dashboard with `python -m streamlit run app/streamlit_app.py`.
2. Select **Add Threat** in the sidebar.
3. Enter the threat details and select **Process Threat**.
4. ThreatMoni appends the record to `data/raw/cybersecurity_dataset.csv`, reruns preprocessing, feature engineering, scoring, and reporting, then displays the new TPI score and priority immediately.
5. Open **Threat Priority** or **Record Explorer** to find the new record among the generated results.

The new record is persisted in the raw dataset, so it remains available after restarting the dashboard.

## What ThreatMoni Does

The framework executes a 10-stage technical workflow:

1. **OSINT Ingestion:** Discovers and validates primary raw OSINT dataset feeds (`Cybersecurity_Dataset.csv`).
2. **Schema Profiling:** Analyzes data quality, column dtypes, missing values, and semantic candidates.
3. **Indicator-Preserving Preprocessing:** Normalizes text while preserving `CVE-*`, IPv4 addresses, cryptographic hashes, and MITRE IDs.
4. **Entity Extraction:** Extracts structured indicator counts, security domain keywords, and TF-IDF n-grams.
5. **Feature Engineering:** Constructs statistical quality proxies, text detail metrics, and indicator density features.
6. **Threat Scoring:** Computes Source Credibility (SCS), Threat Frequency (TFS), Intelligence Quality (IQ), Threat Confidence (TCS), Threat Risk (TRS), and Threat Priority Index (TPI).
7. **Machine Learning Benchmarking:** Trains 6 classifiers (Logistic Regression, Decision Tree, Random Forest, SVM, Naive Bayes, XGBoost).
8. **Threat Prioritization:** Maps continuous TPI scores into Low, Medium, High, and Critical risk tiers.
9. **Horizon Scanning:** Identifies high-priority emerging categories, attack vector hotspots, and geographical threat distributions.
10. **Automated Reporting:** Generates Excel workbooks, research tables (Tables 1–9), high-resolution figures, and an interactive Streamlit dashboard.

---

## System Architecture

ThreatMoni implements a comprehensive 9-layer OSINT system architecture connecting data acquisition, web mining, preprocessing, entity extraction, feature engineering, machine learning modeling, horizon scanning, visualization, and decision support outputs.

<p align="center">
  <img src="assets/architecture_diagram.png" alt="ThreatMoni System Architecture Diagram" width="85%"/>
</p>

```mermaid
flowchart TD
    subgraph L1 ["Layer 1: OSINT Data Ingestion"]
        L1A["News Websites"] --- L1B["RSS Feeds"] --- L1C["CVE & NVD Databases"]
        L1D["Security Blogs & CERT Feeds"] --- L1E["GitHub Repos & Threat Reports"]
    end

    subgraph L2 ["Layer 2: Web Mining & Data Collection"]
        L2A["Web Crawling & API Extraction"] --> L2B["RSS & HTML Parsing"]
        L2B --> L2C["Metadata & Content Extraction"]
    end

    subgraph L3 ["Layer 3: Data Preprocessing"]
        L3A["Data Cleaning & Deduplication"] --> L3B["Missing Value Handling & Noise Filtering"]
        L3B --> L3C["Tokenization & Indicator Preservation"]
    end

    subgraph L4 ["Layer 4: Threat Intelligence Extraction & Correlation"]
        L4A["Source Credibility Assessment"] --> L4B["Named Entity Recognition (NER)"]
        L4B --> L4C["IOC & Technical Extraction"]
        L4C <--> L4D[("Threat Knowledge Base")]
    end

    subgraph L5 ["Layer 5: Feature Engineering"]
        L5A["Threat Frequency & Severity"] --> L5B["Source Reliability & Attack Category"]
        L5B --> L5C["Geographic & Temporal Feature Vectors"]
    end

    subgraph L6 ["Layer 6: Machine Learning & Modeling"]
        L6A["Classifiers: Random Forest, XGBoost"] --- L6B["Anomaly Detection & NLP Models"]
        L6A <--> L6C[("Model Repository")]
    end

    subgraph L7 ["Layer 7: Horizon Scanning & Prioritization"]
        L7A["Emerging Threat Detection"] --> L7B["Risk Prediction & Threat Prioritization"]
    end

    subgraph L8 ["Layer 8: Visualization & Dashboard"]
        L8A["Streamlit Interactive Dashboard"] --> L8B["Threat Maps, Timelines & Reports"]
    end

    subgraph L9 ["Layer 9: Outputs & Decision Support"]
        L9A["Cyber Threat Intelligence"] --> L9B["Threat Horizon Forecasts & Security Alerts"]
    end

    L1C --> L2A
    L2C --> L3A
    L3C --> L4A
    L4C --> L5A
    L5C --> L6A
    L6B --> L7A
    L7B --> L8A
    L8B --> L9A
```

*For detailed component specifications, see [Architecture Documentation](docs/architecture/architecture.md).*

---

## Core Framework Algorithm (Algorithm 1)

ThreatMoni processes multi-source OSINT intelligence through a formal 21-step monitoring and threat score evaluation algorithm:

```text
Algorithm 1. ThreatMoni — Multi-Source Threat Monitoring and Intelligence Algorithm
===================================================================================
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
===================================================================================
```

### Algorithm Step Implementation Mapping

| Operational Stage | Algorithm Steps | Code Implementation Modules | Core Technical Responsibility |
| :--- | :--- | :--- | :--- |
| **Feed Ingestion & Validation** | Steps 1–3 | [`src/threatmoni/data_loader.py`](src/threatmoni/data_loader.py)<br>[`src/threatmoni/profiler.py`](src/threatmoni/profiler.py) | OSINT dataset discovery, schema profiling, entry validation |
| **Indicator Preprocessing** | Step 4 | [`src/threatmoni/preprocessing.py`](src/threatmoni/preprocessing.py) | Technical indicator regex preservation (`CVE`, IPs, Hashes), text cleaning |
| **Extraction & Knowledge Base** | Steps 5–9 | [`src/threatmoni/nlp_engine.py`](src/threatmoni/nlp_engine.py)<br>[`src/threatmoni/entity_extraction.py`](src/threatmoni/entity_extraction.py) | Source Credibility (SCS), entity recognition, indicator mapping |
| **Feature Engineering & Scoring** | Steps 10–13, 17 | [`src/threatmoni/feature_engineering.py`](src/threatmoni/feature_engineering.py)<br>[`src/threatmoni/threat_scoring.py`](src/threatmoni/threat_scoring.py) | TFS, IQ, TCS, TRS, and TPI formula evaluations (Eq. 1–5) |
| **ML Modeling & Horizon Scanning** | Steps 14–16 | [`src/threatmoni/model_training.py`](src/threatmoni/model_training.py)<br>[`src/threatmoni/horizon_scanning.py`](src/threatmoni/horizon_scanning.py) | 6 ML classifiers, emerging threat trend detection |
| **Alerting & Dashboard** | Steps 18–19 | [`src/threatmoni/reporting.py`](src/threatmoni/reporting.py)<br>[`app/streamlit_app.py`](app/streamlit_app.py) | Automated report generation, interactive Streamlit interface |
| **Analyst Feedback Loop** | Steps 20–21 | [`src/threatmoni/pipeline.py`](src/threatmoni/pipeline.py) | Iterative pipeline orchestration & feedback integration |

*For complete step specifications, see [Algorithm Documentation](docs/methodology/algorithm.md).*

---

## Threat Scoring Methodology

ThreatMoni implements a multi-factor scoring model to evaluate threat reports:

### 1. Source Credibility Score (SCS)
$$\text{SCS} = \frac{R + U + C + A}{4} \times 100$$
*Where $R$ = Reliability, $U$ = Update Frequency/Detail, $C$ = Category Consistency, $A$ = Threat Actor Reputation Proxy.*

### 2. Threat Frequency Score (TFS)
$$\text{TFS} = \frac{N_t}{N}$$
*Where $N_t$ = occurrences of threat category $t$, $N$ = total baseline records ($1,100$).*

### 3. Intelligence Quality (IQ)
$$\text{IQ} = \left(0.4 \times \text{Completeness} + 0.3 \times \text{IOC Presence} + 0.3 \times \text{Text Detail}\right) \times 100$$

### 4. Threat Confidence Score (TCS)
$$\text{TCS} = \alpha(\text{SCS}) + \beta(\text{IQ}) \quad (\text{Default } \alpha=0.5, \beta=0.5)$$

### 5. Threat Risk Score (TRS)
$$\text{TRS} = \sum (W_i \times F_i)$$
*Weighted combination of raw severity rating, TFS, risk level prediction, IOC density, and forum sentiment.*

### 6. Threat Priority Index (TPI)
$$\text{TPI} = \frac{\text{TRS} \times \text{TCS}}{100}$$

### Priority Thresholds

| TPI Score | Priority Tier | Description |
| --------: | :------------ | :---------- |
| **0 – 25** | **Low** | Background activity; low indicator density |
| **26 – 50** | **Medium** | Standard threat activity; moderate severity |
| **51 – 75** | **High** | High-severity threat vector; validated indicators |
| **76 – 100**| **Critical** | Urgent emerging threat; critical operational risk |

*Detailed mathematical derivations are available in [Threat Scoring Methodology](docs/methodology/threat_scoring.md).*

---

## Machine Learning Benchmark

The framework benchmarks 6 machine learning models on $N = 1,100$ OSINT records ($80/20$ stratified train/test split, random seed = 42) predicting `Threat Category` (DDoS, Malware, Phishing, Ransomware):

| Model | Accuracy | Precision (Macro) | Recall (Macro) | F1 Score (Weighted) |
| :--- | :---: | :---: | :---: | :---: |
| **Random Forest** | **0.4636** | **0.4586** | **0.4595** | **0.4624** |
| **Support Vector Machine** | 0.4409 | 0.4167 | 0.4276 | 0.4230 |
| **Naive Bayes** | 0.4409 | 0.4406 | 0.4423 | 0.4353 |
| **Decision Tree** | 0.4364 | 0.4331 | 0.4334 | 0.4348 |
| **Logistic Regression** | 0.4364 | 0.4257 | 0.4280 | 0.4301 |
| **XGBoost** | 0.4000 | 0.3942 | 0.3955 | 0.3987 |

### Model Benchmark Figures

| Model F1 Comparison | Top Feature Importances | Confusion Matrix (Random Forest) |
| :---: | :---: | :---: |
| <img src="outputs/figures/model_f1.png" width="280"/> | <img src="outputs/figures/feature_importance_random_forest.png" width="280"/> | <img src="outputs/figures/confusion_matrix_random_forest.png" width="280"/> |

*Experimental setup details are documented in [Experimental Protocol](docs/experiments/experiment_setup.md) and [Evaluation Results](docs/experiments/evaluation.md).*

---

## Threat Horizon Scanning & Research Figures

Analysis of the OSINT baseline ($N = 1,100$) reveals key threat trends and risk distributions across categories, attack vectors, and geographical locations:

### 1. Dataset & Priority Distribution

| Target Class Distribution | Threat Category Share | Priority Level Distribution | TPI Score Spectrum |
| :---: | :---: | :---: | :---: |
| <img src="outputs/figures/class_distribution.png" width="220"/> | <img src="outputs/figures/threat_category_distribution.png" width="220"/> | <img src="outputs/figures/threat_priority_distribution.png" width="220"/> | <img src="outputs/figures/tpi_distribution.png" width="220"/> |

### 2. Attack Vectors & Geographical Intelligence

| Attack Vector Frequency | Geographical Origin | Threat Actor Breakdown | Raw Severity vs TPI |
| :---: | :---: | :---: | :---: |
| <img src="outputs/figures/attack_vector_frequency.png" width="220"/> | <img src="outputs/figures/geographical_distribution.png" width="220"/> | <img src="outputs/figures/threat_actor_frequency.png" width="220"/> | <img src="outputs/figures/severity_vs_tpi.png" width="220"/> |

### 3. Horizon Priority Spectrum & Risk Predictions

| Emerging Threat Priorities | Raw Risk Level Distribution |
| :---: | :---: |
| <img src="outputs/figures/emerging_threats.png" width="400"/> | <img src="outputs/figures/risk_level_distribution.png" width="400"/> |

---

## Project Structure

```
ThreatMoni-OSINT-Web-Mining-Framework/
│
├── README.md                          # Framework documentation
├── LICENSE                            # MIT open-source license
├── .gitignore                         # Version control ignore rules
├── requirements.txt                   # Dependency manifest
├── pyproject.toml                     # Python package manifest
│
├── assets/
│   ├── logo.png                       # High-resolution ThreatMoni research logo
│   └── architecture_diagram.png       # 9-layer system architecture diagram
│
├── app/
│   └── streamlit_app.py               # Interactive Streamlit dashboard
│
├── configs/
│   ├── config.yaml                    # System runtime configuration
│   └── scoring.yaml                   # Scoring parameters & weights
│
├── data/
│   ├── raw/                           # Raw OSINT feeds (Cybersecurity_Dataset.csv)
│   ├── processed/                     # Preprocessed dataset & engineered features
│   └── README.md                      # Data directory documentation
│
├── src/
│   └── threatmoni/                    # Core Python package modules
│       ├── __init__.py
│       ├── data_loader.py             # Data loading & dataset discovery
│       ├── profiler.py                # Schema profiling & quality metrics
│       ├── preprocessing.py           # Indicator-preserving text cleaning
│       ├── nlp_engine.py              # Regex & NLP indicator extraction
│       ├── entity_extraction.py       # Entity statistical summarization
│       ├── feature_engineering.py     # Feature dataset construction
│       ├── threat_scoring.py          # SCS, TFS, IQ, TCS, TRS, TPI engine
│       ├── model_training.py          # ML classifier training (6 models)
│       ├── evaluation.py              # Performance evaluation & plotting
│       ├── horizon_scanning.py        # Threat horizon analysis
│       ├── visualization.py           # Research figure generation
│       ├── reporting.py               # Report & Excel export engine
│       └── pipeline.py                # Pipeline orchestration
│
├── scripts/
│   ├── run_pipeline.py                # Pipeline execution entrypoint
│   ├── prepare_data.py                # Data preprocessing & feature script
│   └── generate_report.py             # Standalone report generator
│
├── notebooks/                         # Research Jupyter notebooks
│   ├── 01_dataset_exploration.ipynb
│   ├── 02_preprocessing.ipynb
│   ├── 03_feature_engineering.ipynb
│   ├── 04_model_training.ipynb
│   └── 05_threat_horizon_analysis.ipynb
│
├── tests/                             # Unit test suite (100% pass rate)
│   ├── __init__.py
│   ├── test_preprocessing.py
│   ├── test_nlp.py
│   ├── test_scoring.py
│   ├── test_features.py
│   └── test_pipeline.py
│
├── outputs/                           # Research outputs & generated artifacts
│   ├── figures/                       # Publication figures (17 PNGs)
│   ├── tables/                        # Research tables (Tables 1-9 CSVs)
│   ├── predictions/                   # Threat priority predictions CSV
│   ├── models/                        # Saved joblib model artifacts
│   └── reports/                       # Markdown final report & paper results
│
├── docs/                              # Technical research documentation
│   ├── architecture/
│   ├── methodology/
│   ├── experiments/
│   └── research/
│
└── .github/
    └── workflows/
        └── tests.yml                  # GitHub Actions CI workflow
```

---

## Quick Start

### 1. Set Up Environment

Create a virtual environment:

```bash
python -m venv .venv
```

**Activate Virtual Environment:**
- **Windows (PowerShell):**
  ```powershell
  .venv\Scripts\activate
  ```
- **Linux / macOS:**
  ```bash
  source .venv/bin/activate
  ```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run Pipeline

Execute the full 18-step end-to-end framework:

```bash
python scripts/run_pipeline.py
```

### 4. Launch Interactive Dashboard

```bash
streamlit run app/streamlit_app.py
```

---

## Results & Artifacts

All experimental results are generated directly by the pipeline and saved in standard formats:

- **Excel Results Workbook:** [`outputs/ThreatMoni_Results.xlsx`](outputs/ThreatMoni_Results.xlsx)
- **Final Research Report:** [`outputs/reports/ThreatMoni_Final_Report.md`](outputs/reports/ThreatMoni_Final_Report.md)
- **Paper-Ready Findings:** [`outputs/reports/paper_ready_results.md`](outputs/reports/paper_ready_results.md)
- **Data Leakage Check:** [`outputs/leakage_check.md`](outputs/leakage_check.md)
- **Reproducibility Manifest:** [`outputs/reproducibility.json`](outputs/reproducibility.json)

---

## Documentation

Detailed research and technical documentation:

- [Architecture Overview](docs/architecture/architecture.md)
- [Threat Scoring Methodology](docs/methodology/threat_scoring.md)
- [Feature Engineering & Extraction](docs/methodology/feature_engineering.md)
- [Threat Horizon Scanning](docs/methodology/threat_horizon_scanning.md)
- [Experimental Setup](docs/experiments/experiment_setup.md)
- [Evaluation Results](docs/experiments/evaluation.md)
- [Research Notes](docs/research/research_notes.md)

---

## Limitations

- **Static Dataset Scope:** The current baseline evaluates a static OSINT sample ($N = 1,100$). Streaming real-time ingestion requires external API adapters.
- **Proxy Formulations:** Where explicit historical source metadata is omitted from raw feeds, verified proxies based on text detail and actor classification are used (documented in [`scoring_assumptions.md`](outputs/reports/scoring_assumptions.md)).

---

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add AmazingFeature'`).
4. Run unit tests (`pytest tests/ -v`).
5. Open a Pull Request.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


## Author

**Ilamsaravanbalaji.Pa**  
Department of Computer Science and Engineering  
Sri Eshwar College of Engineering  
Coimbatore, Tamil Nadu, India
