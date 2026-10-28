import pytest
import pandas as pd
from threatmoni.threat_scoring import ThreatScorer

def test_tpi_range_and_priority_mapping():
    scorer = ThreatScorer()
    tpi_scores = pd.Series([15.0, 40.0, 60.0, 90.0])
    priorities = scorer.classify_threat_priority(tpi_scores)
    
    assert priorities.tolist() == ["Low", "Medium", "High", "Critical"]

def test_scs_tfs_bounds():
    scorer = ThreatScorer()
    df_sample = pd.DataFrame({
        "Threat Category": ["Malware", "Phishing", "Malware"],
        "Sentiment in Forums": [0.8, 0.4, 0.9],
        "Word Count": [40, 20, 50],
        "Threat Actor": ["Lazarus Group", "Unknown", "APT-28"]
    })
    scs = scorer.compute_scs(df_sample)
    tfs = scorer.compute_tfs(df_sample)
    
    assert (scs >= 0.0).all() and (scs <= 100.0).all()
    assert (tfs >= 0.0).all() and (tfs <= 1.0).all()
