# ThreatMoni Scoring Assumptions & Proxy Methodology

## 1. Source Credibility Score (SCS)
Formula: `SCS = (R + U + C + A) / 4`

- **Reliability (R):** Derived from `Sentiment in Forums` as an indicator of public community validation.
- **Update Frequency (U):** Proxied by normalized `Word Count` reflecting information granularity.
- **Consistency (C):** Measured by consensus matching between `Threat Category`, `Predicted Threat Category`, and `Topic Modeling Labels`.
- **Authority (A):** Proxied by `Threat Actor` categorization (known APT groups receive higher authority weighting than 'Unknown').

## 2. Intelligence Quality (IQ)
Formula: `IQ = 0.4(Completeness) + 0.3(IOC Presence) + 0.3(Text Granularity)`

## 3. Threat Confidence Score (TCS)
Formula: `TCS = α(SCS) + β(IQ)` with configured weights α = 0.5, β = 0.5.

## 4. Threat Risk Score (TRS)
Formula: `TRS = Σ(Wi × Fi)`
- severity_score: 30.0%
- tfs: 25.0%
- risk_level_prediction: 20.0%
- ioc_count: 15.0%
- forum_sentiment: 10.0%

## 5. Threat Priority Index (TPI) & Thresholds
Formula: `TPI = (TRS × TCS) / 100`

- **0–25:** Low
- **26–50:** Medium
- **51–75:** High
- **76–100:** Critical
