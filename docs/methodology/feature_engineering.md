# ThreatMoni Feature Engineering & NLP Extraction

## Overview

The feature engineering layer transforms unstructured OSINT text descriptions and structured metadata into numerical feature vectors suitable for ML classification and scoring.

## Feature Categories

1. **Structured Indicator Features:**
   - `cve_count`: Regex count of `CVE-YYYY-NNNN` identifiers.
   - `ip_count`: Count of IPv4 address occurrences.
   - `hash_count`: Count of MD5/SHA256 hashes.
   - `technique_count`: Count of MITRE ATT&CK technique IDs (`TXXXX`).
   - `ioc_count`: Total combined indicator count.

2. **Text Granularity & Keyword Metrics:**
   - `text_length`: Character length of cleaned text.
   - `token_count`: Alphanumeric token count.
   - `security_keyword_count`: Frequency of cybersecurity domain keywords (`phishing`, `malware`, `ransomware`, `backdoor`, `botnet`, `exploit`).
   - `tfidf_*`: Top 15 TF-IDF n-gram feature columns.

3. **Data Quality & Completeness Proxies:**
   - `record_completeness`: Ratio of non-null, non-unknown attributes per record.
   - `intelligence_quality`: Composite score measuring structured availability and text density.
