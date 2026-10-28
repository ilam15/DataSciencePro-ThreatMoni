import pandas as pd
import numpy as np
import logging
from typing import Dict

logger = logging.getLogger("ThreatMoni.EntityExtraction")

class EntityExtractor:
    """
    Summarizes dataset-wide cybersecurity entities for ThreatMoni reporting.
    """

    def summarize_entities(self, df: pd.DataFrame) -> pd.DataFrame:
        entity_stats = []

        entity_metrics = [
            ("CVE Identifiers", "cve_count"),
            ("Indicators of Compromise (IOCs)", "ioc_count"),
            ("Malware / Ransomware Instances", "malware_count"),
            ("Threat Actors", "actor_count"),
            ("Attack Techniques / Vectors", "technique_count"),
            ("Vulnerability References", "vulnerability_count"),
            ("Security Keywords", "security_keyword_count")
        ]

        for label, col in entity_metrics:
            if col in df.columns:
                total_extracted = int(df[col].sum())
                records_with_entity = int((df[col] > 0).sum())
                pct_records = round(records_with_entity / len(df) * 100, 2)
                mean_per_record = round(float(df[col].mean()), 2)
                max_in_record = int(df[col].max())
            else:
                total_extracted = 0
                records_with_entity = 0
                pct_records = 0.0
                mean_per_record = 0.0
                max_in_record = 0

            entity_stats.append({
                "Entity Category": label,
                "Total Extracted": total_extracted,
                "Records Present": records_with_entity,
                "% of Dataset": f"{pct_records}%",
                "Mean Per Record": mean_per_record,
                "Max Per Record": max_in_record
            })

        summary_df = pd.DataFrame(entity_stats)
        logger.info("Successfully generated cybersecurity entity summary.")
        return summary_df
