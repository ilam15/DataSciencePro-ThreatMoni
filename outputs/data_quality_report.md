# ThreatMoni Data Quality Report

- **Dataset Name:** cybersecurity_dataset.csv
- **Total Rows:** 1,101
- **Total Columns:** 15
- **Duplicates:** 0

## Column Quality Summary

| Column Name | Data Type | Missing Count | Missing % | Unique Values |
| --- | --- | --- | --- | --- |
| Threat Category | str | 0 | 0.0% | 4 |
| IOCs (Indicators of Compromise) | str | 0 | 0.0% | 6 |
| Threat Actor | str | 0 | 0.0% | 5 |
| Attack Vector | str | 0 | 0.0% | 3 |
| Geographical Location | str | 0 | 0.0% | 5 |
| Sentiment in Forums | float64 | 0 | 0.0% | 51 |
| Severity Score | int64 | 0 | 0.0% | 5 |
| Predicted Threat Category | str | 0 | 0.0% | 4 |
| Suggested Defense Mechanism | str | 0 | 0.0% | 5 |
| Risk Level Prediction | int64 | 0 | 0.0% | 5 |
| Cleaned Threat Description | str | 0 | 0.0% | 6 |
| Keyword Extraction | str | 0 | 0.0% | 6 |
| Named Entities (NER) | str | 0 | 0.0% | 6 |
| Topic Modeling Labels | str | 0 | 0.0% | 4 |
| Word Count | int64 | 0 | 0.0% | 40 |

## Identified Semantic Candidates

- **Potential Target Columns:** Threat Category, Predicted Threat Category, Topic Modeling Labels
- **Potential Source Columns:** Geographical Location
- **Potential Severity Columns:** Severity Score, Risk Level Prediction
- **Potential Threat Category Columns:** Threat Category, Predicted Threat Category, Topic Modeling Labels
- **Potential Cve Columns:** None
- **Potential Malware Columns:** None
- **Potential Attack Technique Columns:** Attack Vector
- **Potential Ioc Columns:** IOCs (Indicators of Compromise), Cleaned Threat Description
- **Potential Organization Product Columns:** Threat Actor, Named Entities (NER)
