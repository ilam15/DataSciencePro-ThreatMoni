import os
import glob
import shutil
import pandas as pd
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ThreatMoni.DataLoader")

class DataLoader:
    """
    Locates, validates, and loads OSINT threat intelligence datasets for ThreatMoni.
    """

    def __init__(self, raw_dir: str = "data/raw", workspace_dir: str = "."):
        self.raw_dir = raw_dir
        self.workspace_dir = workspace_dir
        os.makedirs(self.raw_dir, exist_ok=True)

    def discover_datasets(self) -> list:
        """
        Discovers all tabular datasets in workspace and raw directory.
        """
        extensions = ["*.csv", "*.xlsx", "*.xls", "*.json", "*.parquet", "*.tsv"]
        found_files = []
        for ext in extensions:
            found_files.extend(glob.glob(os.path.join(self.workspace_dir, ext)))
            found_files.extend(glob.glob(os.path.join(self.raw_dir, ext)))
        
        # Deduplicate paths
        unique_files = list(set([os.path.abspath(f) for f in found_files]))
        logger.info(f"Discovered {len(unique_files)} potential dataset file(s).")
        return unique_files

    def get_primary_dataset_path(self) -> str:
        return os.path.join(self.raw_dir, "cybersecurity_dataset.csv")

    def load_primary_dataset(self, preferred_filename: str = "cybersecurity_dataset.csv") -> pd.DataFrame:
        """
        Loads the primary OSINT dataset, ensuring it exists in data/raw without modifying originals.
        """
        raw_target_path = os.path.join(self.raw_dir, preferred_filename)
        
        if not os.path.exists(raw_target_path):
            # Look for exact or case-insensitive match in workspace
            discovered = self.discover_datasets()
            matched_file = None
            for filepath in discovered:
                filename = os.path.basename(filepath)
                if filename.lower() == preferred_filename.lower() or "cybersecurity" in filename.lower():
                    matched_file = filepath
                    break
            
            if matched_file and os.path.exists(matched_file):
                logger.info(f"Copying discovered dataset from {matched_file} to {raw_target_path}")
                shutil.copy2(matched_file, raw_target_path)
            else:
                raise FileNotFoundError(f"Could not locate primary dataset matching '{preferred_filename}'.")

        logger.info(f"Loading dataset from: {raw_target_path}")
        df = pd.read_csv(raw_target_path)
        logger.info(f"Successfully loaded dataset with shape {df.shape}.")
        return df

    def load_secondary_text_dataset(self, filename: str = "cyberbert.csv") -> pd.DataFrame:
        """
        Loads optional secondary scraped web text dataset if available.
        """
        raw_target_path = os.path.join(self.raw_dir, filename)
        if not os.path.exists(raw_target_path):
            discovered = self.discover_datasets()
            for filepath in discovered:
                if "cyberbert" in os.path.basename(filepath).lower():
                    shutil.copy2(filepath, raw_target_path)
                    break
        
        if os.path.exists(raw_target_path):
            try:
                df = pd.read_csv(raw_target_path)
                logger.info(f"Loaded secondary dataset '{filename}' with shape {df.shape}.")
                return df
            except Exception as e:
                logger.warning(f"Could not load secondary dataset '{filename}': {e}")
        return pd.DataFrame()
