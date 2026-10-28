import os
import joblib
import pandas as pd
import numpy as np
import logging
from typing import Dict, Tuple

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
import xgboost as xgb

logger = logging.getLogger("ThreatMoni.ModelTraining")

class ThreatClassifier:
    """
    Trains and evaluates 6 candidate machine learning classifiers for ThreatMoni threat classification.
    Enforces strict data leakage protection by fitting scalers and encoders only on training data.
    """

    def __init__(self, random_state: int = 42, models_dir: str = "outputs/models"):
        self.random_state = random_state
        self.models_dir = models_dir
        os.makedirs(self.models_dir, exist_ok=True)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

    def prepare_data(self, df: pd.DataFrame, target_col: str = "Threat Category") -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, list, list]:
        df_ml = df.copy()

        # Exclude target leakage columns (TPI, scores, predictions)
        leakage_cols = [
            "scs_score", "tfs_score", "iq_score", "tcs_score", "trs_score",
            "tpi_score", "threat_priority", "Predicted Threat Category",
            "Risk Level Prediction", "Cleaned Threat Description",
            "IOCs (Indicators of Compromise)", "Keyword Extraction",
            "Named Entities (NER)", "Clean_IOC_Str", "Normalized_Cleaned Threat Description"
        ]

        feature_cols = [c for c in df_ml.columns if c != target_col and c not in leakage_cols]
        
        # Select numeric and encoded categorical features
        X_df = pd.DataFrame()
        for col in feature_cols:
            if pd.api.types.is_numeric_dtype(df_ml[col].dtype):
                X_df[col] = df_ml[col].fillna(0)
            else:
                X_df[col] = LabelEncoder().fit_transform(df_ml[col].astype(str))

        y = self.label_encoder.fit_transform(df_ml[target_col].astype(str))
        class_names = list(self.label_encoder.classes_)
        feature_names = list(X_df.columns)

        # Train / Test split with stratification
        X_train, X_test, y_train, y_test = train_test_split(
            X_df.values, y, test_size=0.2, random_state=self.random_state, stratify=y
        )

        # Scaler fit only on X_train to prevent leakage
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        logger.info(f"Prepared ML data. Train shape: {X_train.shape}, Test shape: {X_test.shape}. Target classes: {class_names}")
        return X_train_scaled, X_test_scaled, y_train, y_test, class_names, feature_names

    def get_models(self) -> Dict[str, object]:
        return {
            "Logistic Regression": LogisticRegression(max_iter=1000, random_state=self.random_state),
            "Decision Tree": DecisionTreeClassifier(random_state=self.random_state),
            "Random Forest": RandomForestClassifier(n_estimators=100, random_state=self.random_state),
            "Support Vector Machine": SVC(probability=True, random_state=self.random_state),
            "Naive Bayes": GaussianNB(),
            "XGBoost": xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=self.random_state)
        }

    def train_all_models(self, df: pd.DataFrame, target_col: str = "Threat Category") -> dict:
        X_train, X_test, y_train, y_test, class_names, feature_names = self.prepare_data(df, target_col=target_col)
        models = self.get_models()
        
        trained_results = {}
        for name, model in models.items():
            logger.info(f"Training {name}...")
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            
            y_proba = None
            if hasattr(model, "predict_proba"):
                try:
                    y_proba = model.predict_proba(X_test)
                except Exception:
                    pass

            # Save model artifact
            save_name = name.lower().replace(" ", "_") + ".joblib"
            joblib.dump(model, os.path.join(self.models_dir, save_name))

            trained_results[name] = {
                "model": model,
                "y_test": y_test,
                "y_pred": y_pred,
                "y_proba": y_proba,
                "class_names": class_names,
                "feature_names": feature_names,
                "X_test": X_test
            }

        return trained_results
