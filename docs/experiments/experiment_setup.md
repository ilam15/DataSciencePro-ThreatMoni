# Experimental Setup & Machine Learning Benchmark Protocol

## Experimental Protocol

- **Dataset Baseline:** `cybersecurity_dataset.csv` ($N = 1,100$ records)
- **Train / Test Split:** 80% Training ($N_{\text{train}} = 880$), 20% Test ($N_{\text{test}} = 220$)
- **Sampling Strategy:** Stratified splitting based on target variable `Threat Category`
- **Random Seed:** `random_state = 42` (fixed for full reproducibility)
- **Data Leakage Control:** Scalers (`StandardScaler`) and label encoders fitted strictly on $X_{\text{train}}$ and transformed on $X_{\text{test}}$. TPI and derived score columns excluded from feature matrix $X$.

## Evaluated Classifiers

1. **Logistic Regression** (`max_iter=1000`)
2. **Decision Tree Classifier**
3. **Random Forest Classifier** (`n_estimators=100`)
4. **Support Vector Machine** (`kernel='rbf'`)
5. **Gaussian Naive Bayes**
6. **XGBoost Classifier** (`eval_metric='mlogloss'`)
