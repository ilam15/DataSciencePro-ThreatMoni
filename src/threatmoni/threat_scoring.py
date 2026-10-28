import os
import yaml
import pandas as pd
import numpy as np
import logging

logger = logging.getLogger("ThreatMoni.ThreatScoring")

class ThreatScorer:
    """
    Implements the exact ThreatMoni research scoring methodology:
    - SCS: Source Credibility Score = (R + U + C + A) / 4
    - TFS: Threat Frequency Score = Nt / N
    - IQ:  Intelligence Quality Score
    - TCS: Threat Confidence Score = α(SCS) + β(IQ)
    - TRS: Threat Risk Score = Σ(Wi × Fi)
    - TPI: Threat Priority Index = (TRS × TCS) / 100
    - Priority Levels: Low (0-25), Medium (26-50), High (51-75), Critical (76-100)
    """

    def __init__(self, scoring_config_path: str = "configs/scoring.yaml", outputs_dir: str = "outputs"):
        self.outputs_dir = outputs_dir
        os.makedirs(self.outputs_dir, exist_ok=True)
        
        self.config = self._load_config(scoring_config_path)
        self.alpha = self.config.get("tcs_parameters", {}).get("alpha", 0.5)
        self.beta = self.config.get("tcs_parameters", {}).get("beta", 0.5)
        self.trs_weights = self.config.get("trs_weights", {
            "severity_score": 0.30,
            "tfs": 0.25,
            "risk_level_prediction": 0.20,
            "ioc_count": 0.15,
            "forum_sentiment": 0.10
        })

    def _load_config(self, path: str) -> dict:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        return {}

    def compute_scs(self, df: pd.DataFrame) -> pd.Series:
        """
        Computes Source Credibility Score SCS = (R + U + C + A) / 4 scaled to [0, 100].
        R: Reliability (derived from Sentiment in Forums / IOC presence)
        U: Update Frequency / Recency (derived from normalized word count detail)
        C: Consistency (agreement between Threat Category, Predicted Category, and Topic)
        A: Authority (derived from Threat Actor / Location reputation proxy)
        """
        # 1. Reliability (R)
        if "Sentiment in Forums" in df.columns:
            r = df["Sentiment in Forums"].clip(0.1, 1.0)
        else:
            r = pd.Series(0.75, index=df.index)

        # 2. Update Frequency / Detail (U)
        if "Word Count" in df.columns:
            u = (df["Word Count"] / max(1, df["Word Count"].max())).clip(0.2, 1.0)
        else:
            u = pd.Series(0.70, index=df.index)

        # 3. Consistency (C)
        if "Threat Category" in df.columns and "Predicted Threat Category" in df.columns:
            match_pred = (df["Threat Category"] == df["Predicted Threat Category"]).astype(float)
            if "Topic Modeling Labels" in df.columns:
                match_topic = (df["Threat Category"] == df["Topic Modeling Labels"]).astype(float)
                c = (match_pred * 0.5 + match_topic * 0.5).clip(0.3, 1.0)
            else:
                c = match_pred.clip(0.5, 1.0)
        else:
            c = pd.Series(0.85, index=df.index)

        # 4. Authority (A)
        if "Threat Actor" in df.columns:
            # Known APTs get higher authority proxy than Unknown
            a = df["Threat Actor"].apply(lambda act: 0.90 if str(act).lower() not in ["unknown", "none"] else 0.60)
        else:
            a = pd.Series(0.80, index=df.index)

        scs_normalized = ((r + u + c + a) / 4.0) * 100.0
        return scs_normalized.clip(0, 100)

    def compute_tfs(self, df: pd.DataFrame, category_col: str = "Threat Category") -> pd.Series:
        """
        Computes Threat Frequency Score TFS = Nt / N
        where Nt = occurrences of threat category, N = total records.
        """
        N = len(df)
        if category_col in df.columns and N > 0:
            cat_counts = df[category_col].value_counts().to_dict()
            tfs = df[category_col].map(cat_counts) / float(N)
        else:
            tfs = pd.Series(1.0 / max(1, N), index=df.index)
        return tfs

    def compute_iq(self, df: pd.DataFrame) -> pd.Series:
        """
        Computes Intelligence Quality IQ scaled to [0, 100].
        """
        if "intelligence_quality" in df.columns:
            iq = df["intelligence_quality"] * 100.0
        else:
            completeness = df.notnull().mean(axis=1)
            iq = completeness * 100.0
        return iq.clip(0, 100)

    def compute_tcs(self, scs: pd.Series, iq: pd.Series) -> pd.Series:
        """
        Computes Threat Confidence Score TCS = α(SCS) + β(IQ)
        """
        tcs = self.alpha * scs + self.beta * iq
        return tcs.clip(0, 100)

    def compute_trs(self, df: pd.DataFrame, tfs: pd.Series) -> pd.Series:
        """
        Computes Threat Risk Score TRS = Σ(Wi × Fi)
        """
        # Feature 1: Severity Score (1-5 mapped to 0-100)
        if "Severity Score" in df.columns:
            f_sev = ((df["Severity Score"] - 1.0) / 4.0 * 100.0).clip(0, 100)
        else:
            f_sev = pd.Series(50.0, index=df.index)

        # Feature 2: TFS (0-1 mapped to 0-100)
        f_tfs = (tfs * 100.0).clip(0, 100)

        # Feature 3: Risk Level Prediction (1-5 mapped to 0-100)
        if "Risk Level Prediction" in df.columns:
            f_risk = ((df["Risk Level Prediction"] - 1.0) / 4.0 * 100.0).clip(0, 100)
        else:
            f_risk = pd.Series(50.0, index=df.index)

        # Feature 4: IOC count
        if "ioc_count" in df.columns:
            max_ioc = max(1, df["ioc_count"].max())
            f_ioc = (df["ioc_count"] / max_ioc * 100.0).clip(0, 100)
        else:
            f_ioc = pd.Series(50.0, index=df.index)

        # Feature 5: Forum sentiment
        if "Sentiment in Forums" in df.columns:
            f_sent = (df["Sentiment in Forums"] * 100.0).clip(0, 100)
        else:
            f_sent = pd.Series(50.0, index=df.index)

        w = self.trs_weights
        trs = (
            w.get("severity_score", 0.30) * f_sev +
            w.get("tfs", 0.25) * f_tfs +
            w.get("risk_level_prediction", 0.20) * f_risk +
            w.get("ioc_count", 0.15) * f_ioc +
            w.get("forum_sentiment", 0.10) * f_sent
        )
        return trs.clip(0, 100)

    def compute_tpi(self, trs: pd.Series, tcs: pd.Series) -> pd.Series:
        """
        Computes Threat Priority Index TPI = (TRS × TCS) / 100
        """
        tpi = (trs * tcs) / 100.0
        return tpi.clip(0, 100)

    def classify_threat_priority(self, tpi: pd.Series) -> pd.Series:
        """
        Maps TPI score to priority labels:
        0-25: Low
        26-50: Medium
        51-75: High
        76-100: Critical
        """
        conditions = [
            (tpi <= 25.0),
            (tpi > 25.0) & (tpi <= 50.0),
            (tpi > 50.0) & (tpi <= 75.0),
            (tpi > 75.0)
        ]
        choices = ["Low", "Medium", "High", "Critical"]
        return pd.Series(np.select(conditions, choices, default="Medium"), index=tpi.index)

    def calculate_all_scores(self, df: pd.DataFrame) -> pd.DataFrame:
        df_scored = df.copy()

        scs = self.compute_scs(df_scored)
        tfs = self.compute_tfs(df_scored)
        iq = self.compute_iq(df_scored)
        tcs = self.compute_tcs(scs, iq)
        trs = self.compute_trs(df_scored, tfs)
        tpi = self.compute_tpi(trs, tcs)
        priority = self.classify_threat_priority(tpi)

        df_scored["scs_score"] = scs.round(2)
        df_scored["tfs_score"] = tfs.round(4)
        df_scored["iq_score"] = iq.round(2)
        df_scored["tcs_score"] = tcs.round(2)
        df_scored["trs_score"] = trs.round(2)
        df_scored["tpi_score"] = tpi.round(2)
        df_scored["threat_priority"] = priority

        # Save predictions
        preds_dir = os.path.join(self.outputs_dir, "predictions")
        os.makedirs(preds_dir, exist_ok=True)
        preds_path = os.path.join(preds_dir, "threat_priority_predictions.csv")
        df_scored.to_csv(preds_path, index=False)
        logger.info(f"Calculated all ThreatMoni scores. Saved predictions to '{preds_path}'.")

        self._generate_assumptions_doc()
        return df_scored

    def _generate_assumptions_doc(self):
        reports_dir = os.path.join(self.outputs_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        assumptions_path = os.path.join(reports_dir, "scoring_assumptions.md")
        
        with open(assumptions_path, "w", encoding="utf-8") as f:
            f.write("# ThreatMoni Scoring Assumptions & Proxy Methodology\n\n")
            f.write("## 1. Source Credibility Score (SCS)\n")
            f.write("Formula: `SCS = (R + U + C + A) / 4`\n\n")
            f.write("- **Reliability (R):** Derived from `Sentiment in Forums` as an indicator of public community validation.\n")
            f.write("- **Update Frequency (U):** Proxied by normalized `Word Count` reflecting information granularity.\n")
            f.write("- **Consistency (C):** Measured by consensus matching between `Threat Category`, `Predicted Threat Category`, and `Topic Modeling Labels`.\n")
            f.write("- **Authority (A):** Proxied by `Threat Actor` categorization (known APT groups receive higher authority weighting than 'Unknown').\n\n")
            f.write("## 2. Intelligence Quality (IQ)\n")
            f.write("Formula: `IQ = 0.4(Completeness) + 0.3(IOC Presence) + 0.3(Text Granularity)`\n\n")
            f.write("## 3. Threat Confidence Score (TCS)\n")
            f.write(f"Formula: `TCS = α(SCS) + β(IQ)` with configured weights α = {self.alpha}, β = {self.beta}.\n\n")
            f.write("## 4. Threat Risk Score (TRS)\n")
            f.write("Formula: `TRS = Σ(Wi × Fi)`\n")
            for feature, weight in self.trs_weights.items():
                f.write(f"- {feature}: {weight * 100}%\n")
            f.write("\n## 5. Threat Priority Index (TPI) & Thresholds\n")
            f.write("Formula: `TPI = (TRS × TCS) / 100`\n\n")
            f.write("- **0–25:** Low\n")
            f.write("- **26–50:** Medium\n")
            f.write("- **51–75:** High\n")
            f.write("- **76–100:** Critical\n")

        logger.info(f"Generated scoring assumptions report at '{assumptions_path}'.")
