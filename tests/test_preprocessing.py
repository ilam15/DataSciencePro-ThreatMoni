import pytest
import pandas as pd
from threatmoni.preprocessing import DataPreprocessor

def test_preprocessing_preserves_cve_and_ip(tmp_path):
    preprocessor = DataPreprocessor(processed_dir=str(tmp_path), outputs_dir=str(tmp_path))
    df_sample = pd.DataFrame({
        "Threat Category": ["Malware"],
        "Cleaned Threat Description": ["Attacker exploited CVE-2024-12345 from IP 192.168.1.100 using T1059."]
    })
    df_clean = preprocessor.preprocess(df_sample)
    cleaned_text = df_clean["Normalized_Cleaned Threat Description"].iloc[0]
    
    assert "cve-2024-12345" in cleaned_text.lower()
    assert "192.168.1.100" in cleaned_text
    assert "t1059" in cleaned_text.lower()

def test_preprocessing_deduplication():
    preprocessor = DataPreprocessor()
    df_sample = pd.DataFrame({
        "Threat Category": ["DDoS", "DDoS"],
        "Cleaned Threat Description": ["Identical text", "Identical text"]
    })
    df_clean = preprocessor.preprocess(df_sample)
    assert len(df_clean) == 1
