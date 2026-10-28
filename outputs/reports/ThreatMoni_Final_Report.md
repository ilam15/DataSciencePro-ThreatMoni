# ThreatMoni: OSINT Web Mining Framework for Threat Horizon Scanning
## Comprehensive Research Implementation & Experimental Evaluation Report

### 1. Project Overview
ThreatMoni is an automated OSINT web mining and threat intelligence scoring framework. It ingests cybersecurity intelligence data, performs natural language threat entity extraction, computes Source Credibility (SCS), Intelligence Quality (IQ), Threat Confidence (TCS), Threat Risk (TRS), and Threat Priority Index (TPI) metrics, and trains machine learning models to classify threat categories.

### 2. Dataset Description & Statistics
- **Primary OSINT Dataset:** `cybersecurity_dataset.csv`
- **Total Ingested Records:** 1,101
- **Total Columns:** 54
- **Missing Values:** 0 (Cleaned & Imputed)

### 3. Preprocessing & NLP Entity Extraction
Preserved raw regex structures for CVEs, IP addresses, hashes, and MITRE ATT&CK techniques. Extracted threat intelligence entity metrics across all records:

| Entity Category | Total Extracted | Records Present | % of Dataset |
| --- | --- | --- | --- |
| CVE Identifiers | 1 | 1 | 0.09% |
| Indicators of Compromise (IOCs) | 1979 | 1101 | 100.0% |
| Malware / Ransomware Instances | 551 | 551 | 50.05% |
| Threat Actors | 824 | 824 | 74.84% |
| Attack Techniques / Vectors | 0 | 0 | 0.0% |
| Vulnerability References | 1 | 1 | 0.09% |
| Security Keywords | 1307 | 921 | 83.65% |

### 4. Threat Scoring & Priority Index (TPI) Results
- **Mean TPI Score:** 33.55
- **Min TPI Score:** 10.42
- **Max TPI Score:** 63.1

#### Threat Priority Level Breakdown:
- **Low Priority (0–25):** 243 (22.07%)
- **Medium Priority (26–50):** 801 (72.75%)
- **High Priority (51–75):** 57 (5.18%)
- **Critical Priority (76–100):** 0 (0.0%)

### 5. Machine Learning Model Benchmark
Target Column: `Threat Category` (4 Classes: DDoS, Malware, Phishing, Ransomware)

| Model | Accuracy | Precision (Macro) | Recall (Macro) | F1 Score (Weighted) |
| --- | --- | --- | --- | --- |
| Random Forest | 0.4434 | 0.4373 | 0.4384 | 0.4415 |
| Decision Tree | 0.4208 | 0.4163 | 0.4171 | 0.4197 |
| XGBoost | 0.4163 | 0.4123 | 0.4125 | 0.4156 |
| Logistic Regression | 0.4208 | 0.4077 | 0.4123 | 0.4136 |
| Support Vector Machine | 0.4163 | 0.3801 | 0.4014 | 0.3892 |
| Naive Bayes | 0.4570 | 0.3167 | 0.4366 | 0.3720 |

**Best Performing Model:** `Random Forest` (Accuracy: 0.4434, Weighted F1: 0.4415)

### 6. Threat Horizon Scanning & Findings
Horizon scanning revealed Ransomware and Phishing campaigns as top threat drivers based on mean TPI scores. Network vulnerabilities and email vectors exhibit the highest risk density.

### 7. Generated Artifacts & Verification
- Streamlit Dashboard: `app/streamlit_app.py`
- Research Tables: `outputs/tables/*.csv`
- High-Res Figures: `outputs/figures/*.png`
- Excel Workbook: `outputs/ThreatMoni_Results.xlsx`
