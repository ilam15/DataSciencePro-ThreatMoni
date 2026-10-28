import sys
import os
import pytest
import pandas as pd
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from threatmoni.data_loader import DataLoader
from threatmoni.preprocessing import DataPreprocessor
from threatmoni.nlp_engine import NLPEngine
from threatmoni.feature_engineering import FeatureEngineer
from threatmoni.threat_scoring import ThreatScorer
# pyrefly: ignore [missing-import]
from threatmoni.model_training import ThreatClassifier
from threatmoni.evaluation import ModelEvaluator
from threatmoni.pipeline import ThreatMoniPipeline

def test_01_dataset_loading():
    loader = DataLoader(raw_dir="data/raw")
    df = loader.load_primary_dataset()
    assert isinstance(df, pd.DataFrame)
    assert len(df) > 0
    assert "Threat Category" in df.columns

def test_02_preprocessing(tmp_path):
    preprocessor = DataPreprocessor(processed_dir=str(tmp_path), outputs_dir=str(tmp_path))
    df_sample = pd.DataFrame({
        "Threat Category": ["Malware", "Phishing"],
        "Cleaned Threat Description": ["Sample attack CVE-2024-1234 on IP 192.168.1.1", "Phishing email link"]
    })
    df_clean = preprocessor.preprocess(df_sample)
    assert len(df_clean) == 2
    assert "Normalized_Cleaned Threat Description" in df_clean.columns

def test_03_cve_and_ioc_extraction():
    engine = NLPEngine()
    text = "Attack exploiting CVE-2024-9999 from host 10.0.0.1 and hash a1b2c3d4e5f678901234567890123456"
    extracted = engine.extract_indicators_from_text(text)
    assert "CVE-2024-9999" in extracted["cves"]
    assert "10.0.0.1" in extracted["ips"]
    assert len(extracted["hashes"]) == 1

def test_04_tfs_calculation():
    scorer = ThreatScorer()
    df_sample = pd.DataFrame({"Threat Category": ["Malware", "Malware", "Phishing", "DDoS"]})
    tfs = scorer.compute_tfs(df_sample)
    assert (tfs >= 0.0).all() and (tfs <= 1.0).all()
    assert tfs.iloc[0] == 2.0 / 4.0

def test_05_scs_calculation():
    scorer = ThreatScorer()
    df_sample = pd.DataFrame({
        "Sentiment in Forums": [0.9, 0.5],
        "Word Count": [100, 50],
        "Threat Category": ["DDoS", "Malware"],
        "Predicted Threat Category": ["DDoS", "Malware"],
        "Threat Actor": ["APT-28", "Unknown"]
    })
    scs = scorer.compute_scs(df_sample)
    assert (scs >= 0.0).all() and (scs <= 100.0).all()

def test_06_tcs_calculation():
    scorer = ThreatScorer()
    scs = pd.Series([80.0, 60.0])
    iq = pd.Series([90.0, 70.0])
    tcs = scorer.compute_tcs(scs, iq)
    assert tcs.iloc[0] == 0.5 * 80.0 + 0.5 * 90.0  # 85.0
    assert (tcs >= 0.0).all() and (tcs <= 100.0).all()

def test_07_trs_and_tpi_calculation():
    scorer = ThreatScorer()
    df_sample = pd.DataFrame({
        "Severity Score": [5, 1],
        "Risk Level Prediction": [5, 1],
        "ioc_count": [10, 1],
        "Sentiment in Forums": [0.9, 0.2]
    })
    tfs = pd.Series([0.5, 0.1])
    trs = scorer.compute_trs(df_sample, tfs)
    tcs = pd.Series([80.0, 50.0])
    tpi = scorer.compute_tpi(trs, tcs)
    
    assert (trs >= 0.0).all() and (trs <= 100.0).all()
    assert (tpi >= 0.0).all() and (tpi <= 100.0).all()

def test_08_risk_classification():
    scorer = ThreatScorer()
    tpi_scores = pd.Series([10.0, 35.0, 65.0, 85.0])
    priority = scorer.classify_threat_priority(tpi_scores)
    assert priority.tolist() == ["Low", "Medium", "High", "Critical"]

def test_09_feature_generation(tmp_path):
    fe = FeatureEngineer(processed_dir=str(tmp_path))
    df_sample = pd.DataFrame({
        "Threat Category": ["DDoS", "Malware"],
        "Cleaned Threat Description": ["DDoS attack on web server", "Malware infection via email attachment"],
        "IOCs (Indicators of Compromise)": ["['1.1.1.1']", "['2.2.2.2']"]
    })
    df_feat = fe.build_features(df_sample)
    assert "intelligence_quality" in df_feat.columns
    assert "record_completeness" in df_feat.columns

def test_10_model_training_and_evaluation():
    classifier = ThreatClassifier()
    evaluator = ModelEvaluator()
    
    df_sample = pd.DataFrame({
        "Threat Category": ["DDoS", "Malware", "Phishing", "Ransomware"] * 10,
        "Severity Score": [1, 3, 4, 5] * 10,
        "Word Count": [20, 30, 40, 50] * 10,
        "Sentiment in Forums": [0.2, 0.5, 0.7, 0.9] * 10
    })
    
    df_scored = ThreatScorer().calculate_all_scores(df_sample)
    results = classifier.train_all_models(df_scored, target_col="Threat Category")
    assert "Random Forest" in results
    
    comp_df = evaluator.evaluate_all(results)
    assert isinstance(comp_df, pd.DataFrame)
    assert "F1 Score (Weighted)" in comp_df.columns

def test_11_full_pipeline_execution():
    pipeline = ThreatMoniPipeline()
    df_scored, model_comp = pipeline.run()
    assert len(df_scored) > 0
    assert len(model_comp) > 0
