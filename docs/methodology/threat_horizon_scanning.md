# Threat Horizon Scanning Methodology

## Purpose

Threat Horizon Scanning synthesizes output metrics from the scoring engine and NLP feature extraction layer to detect emerging threat vectors, prioritize high-risk OSINT records, and analyze sector/category distributions.

## Scanning Workflow

1. **Threat Category Prioritization:** Groups records by category (`DDoS`, `Malware`, `Phishing`, `Ransomware`) and computes mean TPI scores to rank threat domains by severity.
2. **Priority Concentration Analysis:** Evaluates the proportion of records assigned to `High` or `Critical` TPI tiers.
3. **Attack Vector Distribution:** Identifies dominant infection and delivery mechanisms (`Email`, `Network`, `Web`).
4. **Geographical Intelligence Mapping:** Aggregates threat origins (`North Korea`, `USA`, `Russia`, `China`, `Global`).
