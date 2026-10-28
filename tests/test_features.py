import pytest
import pandas as pd
from threatmoni.feature_engineering import FeatureEngineer

def test_feature_engineering_builds_quality_metrics(tmp_path):
    fe = FeatureEngineer(processed_dir=str(tmp_path))
    df_sample = pd.DataFrame({
        "Threat Category": ["DDoS"],
        "Cleaned Threat Description": ["DDoS attack targeting corporate DNS servers"],
        "IOCs (Indicators of Compromise)": ["['192.168.1.1']"]
    })
    df_feat = fe.build_features(df_sample)
    
    assert "intelligence_quality" in df_feat.columns
    assert "record_completeness" in df_feat.columns
    assert "token_count" in df_feat.columns
