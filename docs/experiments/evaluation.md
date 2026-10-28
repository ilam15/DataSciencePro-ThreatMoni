# Benchmark Evaluation Results

## Model Performance Summary

Evaluated on $N=220$ holdout test records:

| Model | Accuracy | Precision (Macro) | Recall (Macro) | F1 Score (Weighted) |
| --- | --- | --- | --- | --- |
| **Random Forest** | **0.4636** | **0.4586** | **0.4595** | **0.4624** |
| Support Vector Machine | 0.4409 | 0.4167 | 0.4276 | 0.4230 |
| Naive Bayes | 0.4409 | 0.4406 | 0.4423 | 0.4353 |
| Decision Tree | 0.4364 | 0.4331 | 0.4334 | 0.4348 |
| Logistic Regression | 0.4364 | 0.4257 | 0.4280 | 0.4301 |
| XGBoost | 0.4000 | 0.3942 | 0.3955 | 0.3987 |

## Key Findings

- **Random Forest** achieved the highest weighted F1 score ($0.4624$) and accuracy ($46.36\%$).
- Feature importance analysis reveals `token_count`, `text_length`, `ioc_count`, and `Sentiment in Forums` as top predictive features.
- Confusion matrices and comparative figures are saved under `outputs/figures/`.
