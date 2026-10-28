import os
import pandas as pd
import numpy as np
import logging
from .nlp_engine import NLPEngine

logger = logging.getLogger("ThreatMoni.FeatureEngineering")

class FeatureEngineer:
    """
    Constructs the complete ThreatMoni feature dataset combining text metrics,
    threat intelligence indicators, source proxies, and statistical quality features.
    """

    def __init__(self, processed_dir: str = "data/processed"):
        self.processed_dir = processed_dir
        self.nlp_engine = NLPEngine()

    def build_features(self, df: pd.DataFrame) -> pd.DataFrame:
        df_feat = df.copy()

        # 1. NLP and Indicator Features
        df_feat = self.nlp_engine.process_dataframe(df_feat)
        
        # Text features
        text_col = "Cleaned Threat Description" if "Cleaned Threat Description" in df_feat.columns else df_feat.columns[0]
        df_feat["text_length"] = df_feat[text_col].fillna("").astype(str).apply(len)
        df_feat["token_count"] = df_feat[text_col].fillna("").astype(str).apply(lambda s: len(s.split()))

        # TF-IDF Features
        tfidf_df = self.nlp_engine.compute_tfidf_features(df_feat, text_col=text_col, max_features=15)
        df_feat = pd.concat([df_feat, tfidf_df], axis=1)

        # 2. Statistical & Quality Features
        # Record Completeness: ratio of non-null, non-unknown fields
        non_empty_counts = df_feat.apply(lambda row: sum(1 for v in row if str(v).lower() not in ["unknown", "none", "", "nan"]), axis=1)
        df_feat["record_completeness"] = non_empty_counts / len(df_feat.columns)

        # Intelligence Quality (IQ)
        df_feat["intelligence_quality"] = (
            0.4 * df_feat["record_completeness"] +
            0.3 * (df_feat["ioc_count"] > 0).astype(float) +
            0.3 * (df_feat["token_count"] / df_feat["token_count"].max()).clip(0, 1)
        )

        # 3. Source Proxies
        if "Geographical Location" in df_feat.columns:
            loc_counts = df_feat["Geographical Location"].value_counts(normalize=True).to_dict()
            df_feat["source_frequency"] = df_feat["Geographical Location"].map(loc_counts).fillna(0.1)
        else:
            df_feat["source_frequency"] = 0.5

        if "Threat Actor" in df_feat.columns:
            actor_counts = df_feat["Threat Actor"].value_counts(normalize=True).to_dict()
            df_feat["actor_frequency"] = df_feat["Threat Actor"].map(actor_counts).fillna(0.1)
        else:
            df_feat["actor_frequency"] = 0.5

        # Save feature dataset
        out_path = os.path.join(self.processed_dir, "threatmoni_features.csv")
        df_feat.to_csv(out_path, index=False)
        logger.info(f"Built ThreatMoni features dataset with {df_feat.shape[1]} columns. Saved to '{out_path}'.")

        return df_feat
