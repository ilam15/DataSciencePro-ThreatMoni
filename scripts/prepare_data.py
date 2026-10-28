import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from threatmoni.data_loader import DataLoader
from threatmoni.profiler import DatasetProfiler
from threatmoni.preprocessing import DataPreprocessor
from threatmoni.feature_engineering import FeatureEngineer

def prepare_data():
    print("[1/4] Loading raw OSINT dataset...")
    loader = DataLoader(raw_dir="data/raw")
    loader.discover_datasets()
    df_raw = loader.load_primary_dataset()

    print("[2/4] Profiling dataset schema...")
    profiler = DatasetProfiler(output_dir="outputs")
    profiler.profile_dataset(df_raw)

    print("[3/4] Cleaning & preserving cybersecurity indicators...")
    preprocessor = DataPreprocessor(processed_dir="data/processed", outputs_dir="outputs")
    df_clean = preprocessor.preprocess(df_raw)

    print("[4/4] Engineering ThreatMoni features...")
    fe = FeatureEngineer(processed_dir="data/processed")
    df_feat = fe.build_features(df_clean)

    print(f"Successfully prepared dataset: {df_feat.shape[0]} rows, {df_feat.shape[1]} features.")

if __name__ == "__main__":
    prepare_data()
