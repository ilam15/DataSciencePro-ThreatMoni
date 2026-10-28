import os
import re
import pandas as pd
import numpy as np
import logging
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

logger = logging.getLogger("ThreatMoni.Preprocessing")

class DataPreprocessor:
    """
    Cleans and preprocesses cybersecurity OSINT data while carefully preserving
    technical cybersecurity indicators (CVEs, IOCs, IP addresses, hashes, malware names, etc.).
    """

    def __init__(self, processed_dir: str = "data/processed", outputs_dir: str = "outputs"):
        self.processed_dir = processed_dir
        self.outputs_dir = outputs_dir
        os.makedirs(self.processed_dir, exist_ok=True)
        os.makedirs(self.outputs_dir, exist_ok=True)

        try:
            self.stop_words = set(stopwords.words('english'))
        except Exception:
            self.stop_words = set()
        self.lemmatizer = WordNetLemmatizer()

    def preserve_clean_text(self, text: str) -> str:
        """
        Cleans unstructured text while preserving cybersecurity indicators like
        CVE-202X-XXXX, IP addresses, hashes, MITRE IDs (T1059), and domain names.
        """
        if not isinstance(text, str) or not text.strip():
            return ""

        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Tokenize while protecting cybersecurity patterns
        # Standard alphanumeric + hyphens + dots for IP/CVE/domains
        words = text.split()
        cleaned_words = []
        for word in words:
            # Check if word is a security indicator (CVE, IP, Hash, Domain, MITRE ID)
            is_cve = bool(re.match(r'^CVE-\d{4}-\d{4,7}$', word, re.IGNORECASE))
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', word))
            is_mitre = bool(re.match(r'^T\d{4}(\.\d{3})?$', word, re.IGNORECASE))
            is_hash = bool(re.match(r'^[a-fA-F0-9]{32,64}$', word))
            
            if is_cve or is_ip or is_mitre or is_hash:
                cleaned_words.append(word)
            else:
                w_lower = word.lower()
                w_clean = re.sub(r'[^a-zA-Z0-9\-\._]', '', w_lower)
                if w_clean and w_clean not in self.stop_words and len(w_clean) > 1:
                    try:
                        w_clean = self.lemmatizer.lemmatize(w_clean)
                    except Exception:
                        pass
                    cleaned_words.append(w_clean)

        return " ".join(cleaned_words)

    def preprocess(self, df: pd.DataFrame) -> pd.DataFrame:
        orig_row_count = len(df)
        df_clean = df.copy()

        # 1. Remove duplicate records
        df_clean = df_clean.drop_duplicates().reset_index(drop=True)
        dedup_count = orig_row_count - len(df_clean)

        # 2. Fill missing values safely
        for col in df_clean.columns:
            if pd.api.types.is_numeric_dtype(df_clean[col].dtype):
                df_clean[col] = df_clean[col].fillna(df_clean[col].median() if not df_clean[col].isnull().all() else 0)
            else:
                df_clean[col] = df_clean[col].fillna("Unknown")

        # 3. Clean text columns
        text_cols = [c for c in df_clean.columns if "description" in c.lower() or "content" in c.lower() or "text" in c.lower()]
        for tcol in text_cols:
            df_clean[f"Normalized_{tcol}"] = df_clean[tcol].apply(self.preserve_clean_text)

        # 4. Clean IOCs column string representation into structured lists/counts
        if "IOCs (Indicators of Compromise)" in df_clean.columns:
            df_clean["Clean_IOC_Str"] = df_clean["IOCs (Indicators of Compromise)"].astype(str).apply(
                lambda s: re.sub(r"[\[\]']", "", s).strip()
            )

        # Save processed dataset
        output_csv = os.path.join(self.processed_dir, "cleaned_dataset.csv")
        df_clean.to_csv(output_csv, index=False)
        logger.info(f"Saved preprocessed dataset to '{output_csv}' with shape {df_clean.shape}.")

        # Generate report
        self._generate_preprocessing_report(orig_row_count, dedup_count, df_clean, text_cols)
        return df_clean

    def _generate_preprocessing_report(self, orig_rows: int, duplicates_removed: int, df_clean: pd.DataFrame, text_cols: list):
        report_path = os.path.join(self.outputs_dir, "preprocessing_report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("# ThreatMoni Preprocessing Report\n\n")
            f.write(f"- **Original Row Count:** {orig_rows:,}\n")
            f.write(f"- **Duplicates Removed:** {duplicates_removed}\n")
            f.write(f"- **Final Cleaned Rows:** {len(df_clean):,}\n")
            f.write(f"- **Total Columns:** {len(df_clean.columns)}\n\n")
            f.write("## Applied Transformations\n")
            f.write("1. **Missing Value Handling:** Replaced missing categorical strings with `'Unknown'`, numerical missing values with column medians.\n")
            f.write("2. **Duplicate Removal:** Exact matching row deduplication applied.\n")
            f.write("3. **Text Normalization:** Lowercased non-indicator terms, tokenized, removed stop-words, applied WordNet lemmatization.\n")
            f.write("4. **Cybersecurity Indicator Protection:** Preserved raw regex structures for CVEs (`CVE-XXXX-XXXX`), IP addresses (`X.X.X.X`), hashes, and MITRE ATT&CK techniques (`TXXXX`).\n")
            f.write("5. **Structured Indicator Formatting:** Cleaned brackets and quotes from IOC lists.\n")

        logger.info(f"Generated preprocessing report at '{report_path}'.")
