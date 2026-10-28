# ThreatMoni Data Directory Guide

This directory manages open-source threat intelligence (OSINT) datasets used by ThreatMoni.

## Directory Structure

```
data/
├── raw/         # Raw, unmodified OSINT input datasets
└── processed/   # Preprocessed, indicator-preserved datasets & engineered features
```

## Data Protocol & Privacy Rules

1. **Original Raw Data Preservation:**
   Files placed in `data/raw/` (e.g. `cybersecurity_dataset.csv`) are strictly read-only inputs. The pipeline never modifies raw files.

2. **Processed Outputs:**
   The preprocessing engine generates:
   - `data/processed/cleaned_dataset.csv`: Sanitized text with preserved cybersecurity indicators (`CVE-*`, IP addresses, hashes, MITRE IDs).
   - `data/processed/threatmoni_features.csv`: Feature-engineered dataset combining indicator counts, text TF-IDF, and quality metrics.

3. **Reproducibility & Custom Data:**
   Researchers can evaluate custom OSINT CSV feeds by placing them in `data/raw/` and referencing them in `configs/config.yaml`.
