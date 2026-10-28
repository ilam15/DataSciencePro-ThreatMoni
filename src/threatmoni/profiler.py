import os
import json
import pandas as pd
import numpy as np
import logging

logger = logging.getLogger("ThreatMoni.Profiler")

class DatasetProfiler:
    """
    Automated profiler for ThreatMoni OSINT datasets.
    Identifies dataset structure, schema, data quality issues, and semantic candidates.
    """

    def __init__(self, output_dir: str = "outputs"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def profile_dataset(self, df: pd.DataFrame, dataset_name: str = "cybersecurity_dataset.csv") -> dict:
        num_rows, num_cols = df.shape
        duplicates = int(df.duplicated().sum())

        missing_counts = df.isnull().sum().to_dict()
        missing_pcts = (df.isnull().sum() / max(1, num_rows) * 100).round(2).to_dict()

        dtypes = {col: str(dtype) for col, dtype in df.dtypes.items()}
        unique_counts = {col: int(df[col].nunique()) for col in df.columns}

        numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        categorical_cols = df.select_dtypes(include=['object', 'category', 'string']).columns.tolist()
        
        text_cols = []
        for col in categorical_cols:
            sample_str = df[col].dropna().astype(str)
            if not sample_str.empty and sample_str.str.len().mean() > 30:
                text_cols.append(col)

        datetime_cols = []
        for col in df.columns:
            if "date" in col.lower() or "time" in col.lower() or "timestamp" in col.lower():
                datetime_cols.append(col)

        semantic_candidates = self._find_semantic_candidates(df)

        profile = {
            "dataset_name": dataset_name,
            "num_rows": num_rows,
            "num_columns": num_cols,
            "column_names": list(df.columns),
            "data_types": dtypes,
            "missing_values": missing_counts,
            "missing_percentage": missing_pcts,
            "duplicate_records": duplicates,
            "unique_values": unique_counts,
            "numerical_columns": numerical_cols,
            "categorical_columns": categorical_cols,
            "text_columns": text_cols,
            "date_time_columns": datetime_cols,
            "semantic_candidates": semantic_candidates
        }

        self._export_profile(profile, df)
        return profile

    def _find_semantic_candidates(self, df: pd.DataFrame) -> dict:
        candidates = {
            "potential_target_columns": [],
            "potential_source_columns": [],
            "potential_severity_columns": [],
            "potential_threat_category_columns": [],
            "potential_cve_columns": [],
            "potential_malware_columns": [],
            "potential_attack_technique_columns": [],
            "potential_ioc_columns": [],
            "potential_organization_product_columns": []
        }

        keywords_map = {
            "potential_target_columns": ["label", "target", "class", "category", "risk_level"],
            "potential_source_columns": ["source", "publisher", "vendor", "location", "geographical"],
            "potential_severity_columns": ["severity", "score", "risk", "level"],
            "potential_threat_category_columns": ["threat category", "threat_type", "attack_type", "topic"],
            "potential_cve_columns": ["cve", "vulnerability"],
            "potential_malware_columns": ["malware", "trojan", "ransomware"],
            "potential_attack_technique_columns": ["attack vector", "technique", "vector"],
            "potential_ioc_columns": ["ioc", "indicators", "ip", "domain", "hash"],
            "potential_organization_product_columns": ["actor", "organization", "product", "entities"]
        }

        for col in df.columns:
            col_lower = col.lower()
            for key, keywords in keywords_map.items():
                if any(kw in col_lower for kw in keywords):
                    candidates[key].append(col)

        return candidates

    def _export_profile(self, profile: dict, df: pd.DataFrame):
        json_path = os.path.join(self.output_dir, "data_profile.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=4)

        csv_summary = []
        for col in df.columns:
            csv_summary.append({
                "column_name": col,
                "data_type": str(df[col].dtype),
                "missing_count": df[col].isnull().sum(),
                "missing_pct": round(df[col].isnull().sum() / len(df) * 100, 2),
                "unique_count": df[col].nunique(),
                "sample_val": str(df[col].dropna().iloc[0]) if not df[col].dropna().empty else ""
            })
        csv_path = os.path.join(self.output_dir, "data_profile.csv")
        pd.DataFrame(csv_summary).to_csv(csv_path, index=False)

        md_path = os.path.join(self.output_dir, "data_quality_report.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# ThreatMoni Data Quality Report\n\n")
            f.write(f"- **Dataset Name:** {profile['dataset_name']}\n")
            f.write(f"- **Total Rows:** {profile['num_rows']:,}\n")
            f.write(f"- **Total Columns:** {profile['num_columns']}\n")
            f.write(f"- **Duplicates:** {profile['duplicate_records']}\n\n")
            f.write(f"## Column Quality Summary\n\n")
            f.write("| Column Name | Data Type | Missing Count | Missing % | Unique Values |\n")
            f.write("| --- | --- | --- | --- | --- |\n")
            for row in csv_summary:
                f.write(f"| {row['column_name']} | {row['data_type']} | {row['missing_count']} | {row['missing_pct']}% | {row['unique_count']} |\n")
            
            f.write(f"\n## Identified Semantic Candidates\n\n")
            for cat, col_list in profile['semantic_candidates'].items():
                f.write(f"- **{cat.replace('_', ' ').title()}:** {', '.join(col_list) if col_list else 'None'}\n")

        logger.info(f"Generated profiling artifacts in '{self.output_dir}'.")
