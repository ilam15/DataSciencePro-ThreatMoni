import os
import pandas as pd
import numpy as np
import logging

logger = logging.getLogger("ThreatMoni.HorizonScanning")

class HorizonScanner:
    """
    Performs OSINT Threat Horizon Scanning analysis.
    Identifies high-priority emerging threats, category distribution,
    vector hotspots, and critical-level risk clusters across the OSINT intelligence baseline.
    """

    def __init__(self, tables_dir: str = "outputs/tables"):
        self.tables_dir = tables_dir
        os.makedirs(self.tables_dir, exist_ok=True)

    def scan_horizon(self, df: pd.DataFrame) -> dict:
        df_scan = df.copy()

        # 1. Category and Priority Distribution Analysis
        cat_dist = df_scan["Threat Category"].value_counts().reset_index()
        cat_dist.columns = ["Threat Category", "Record Count"]
        cat_dist["Percentage"] = (cat_dist["Record Count"] / len(df_scan) * 100).round(2).astype(str) + "%"

        prio_dist = df_scan["threat_priority"].value_counts().reset_index()
        prio_dist.columns = ["Threat Priority", "Record Count"]
        prio_dist["Percentage"] = (prio_dist["Record Count"] / len(df_scan) * 100).round(2).astype(str) + "%"

        # 2. Top High and Critical Risk Threats
        high_critical_df = df_scan[df_scan["threat_priority"].isin(["High", "Critical"])].sort_values(
            by="tpi_score", ascending=False
        )

        top_threats_summary = df_scan.groupby("Threat Category").agg(
            Total_Count=("Threat Category", "count"),
            Mean_TPI=("tpi_score", "mean"),
            Max_TPI=("tpi_score", "max"),
            Critical_Count=("threat_priority", lambda p: (p == "Critical").sum()),
            High_Count=("threat_priority", lambda p: (p == "High").sum()),
            Mean_Severity=("Severity Score", "mean") if "Severity Score" in df_scan.columns else ("tpi_score", "mean")
        ).reset_index().sort_values(by="Mean_TPI", ascending=False)

        top_threats_summary["Mean_TPI"] = top_threats_summary["Mean_TPI"].round(2)
        top_threats_summary["Mean_Severity"] = top_threats_summary["Mean_Severity"].round(2)

        # Save Horizon Tables
        top_threats_summary.to_csv(os.path.join(self.tables_dir, "top_threats.csv"), index=False)
        prio_dist.to_csv(os.path.join(self.tables_dir, "threat_priority_distribution.csv"), index=False)
        
        top_critical_records = high_critical_df.head(20)[[
            "Threat Category", "Threat Actor", "Attack Vector", "tpi_score", "threat_priority", "Cleaned Threat Description"
        ]] if "Cleaned Threat Description" in high_critical_df.columns else high_critical_df.head(20)
        top_critical_records.to_csv(os.path.join(self.tables_dir, "top_high_critical_records.csv"), index=False)

        logger.info("Completed Threat Horizon Scanning analysis.")
        return {
            "category_distribution": cat_dist,
            "priority_distribution": prio_dist,
            "top_threats_summary": top_threats_summary,
            "high_critical_count": len(high_critical_df),
            "critical_count": int((df_scan["threat_priority"] == "Critical").sum())
        }
