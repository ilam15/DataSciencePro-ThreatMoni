# ThreatMoni Research Notes & Design Rationale

## Design Rationale

- **Hybrid Entity Extraction:** Unstructured OSINT threat feeds contain mixed technical indicators (`CVE-*`, IP addresses, hashes) and descriptive prose. Using raw regex extraction alongside NLTK tokenization ensures high-precision indicator capture without relying on heavyweight transformer models when resources are constrained.
- **Formulation of TPI:** Combining Source Credibility (SCS) with Risk (TRS) prevents noisy or low-credibility threat reports from artificially triggering critical alerts.

## Research Limitations

1. **Static Dataset Baseline:** The current baseline operates on static OSINT snapshots ($N = 1,100$). Real-time streaming connectors (e.g. RSS feeds, NVD APIs) represent an operational extension point.
2. **Proxy Feature Dependency:** Where direct historical source authority metadata is absent, proxy features derived from text detail and actor classification are utilized and fully documented in `outputs/reports/scoring_assumptions.md`.
