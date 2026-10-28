import pytest
from threatmoni.nlp_engine import NLPEngine

def test_nlp_indicator_regex():
    engine = NLPEngine()
    sample_text = "Vulnerability CVE-2023-45678 found on 10.0.0.5 with hash c4ca4238a0b923820dcc509a6f75849b and technique T1566."
    res = engine.extract_indicators_from_text(sample_text)
    
    assert "CVE-2023-45678" in res["cves"]
    assert "10.0.0.5" in res["ips"]
    assert "c4ca4238a0b923820dcc509a6f75849b" in res["hashes"]
    assert "T1566" in res["mitre_techniques"]
