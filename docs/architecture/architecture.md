# ThreatMoni Architecture Documentation

## Comprehensive 9-Layer OSINT System Architecture

ThreatMoni implements a multi-tiered cybersecurity intelligence pipeline connecting raw open-source web feeds to prioritized decision support outputs.

<p align="center">
  <img src="../../assets/architecture_diagram.png" alt="ThreatMoni OSINT System Architecture" width="80%"/>
</p>

### System Layers & Functional Components

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

---

### Layer Specifications

1. **OSINT Acquisition Layer:** Collects structured and unstructured intelligence across heterogeneous web sources (News sites, RSS feeds, CVE/NVD vulnerability databases, CERT advisories, security blogs).
2. **Web Mining Layer:** Crawls HTML pages, parses RSS feeds, calls REST APIs, and extracts structural metadata.
3. **Preprocessing Layer:** Removes duplicate entries, imputes missing records, cleans text formatting, and preserves technical indicators (`CVE-*`, IPv4 addresses, cryptographic hashes, MITRE IDs).
4. **Extraction & Correlation Layer:** Evaluates Source Credibility Scores (SCS), performs Named Entity Recognition (NER), extracts IOCs, and links extracted entities to the Threat Knowledge Base.
5. **Feature Engineering Layer:** Constructs multi-dimensional feature vectors including Threat Frequency (TFS), Source Reliability, Attack Vector, Geographic Location, and Intelligence Quality (IQ).
6. **Machine Learning Layer:** Benchmark classifiers (Random Forest, Decision Tree, Logistic Regression, SVM, Naive Bayes, XGBoost) fit on scaled training features ($X_{\text{train}}$) to predict threat categories.
7. **Horizon Scanning Layer:** Synthesizes SCS, TFS, IQ, and Risk Scores to calculate Threat Priority Index (TPI) metrics and identify high/critical priority threats.
8. **Visualization & Dashboard Layer:** Renders real-time interactive figures, comparative tables, record search interfaces, and threat maps.
9. **Decision Support Output Layer:** Exports executive research reports (`ThreatMoni_Final_Report.md`), paper-ready markdown tables, and multi-sheet Excel workbooks (`ThreatMoni_Results.xlsx`).
