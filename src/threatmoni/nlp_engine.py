import re
import pandas as pd
import numpy as np
import logging
from typing import Dict, List, Any
from sklearn.feature_extraction.text import TfidfVectorizer

logger = logging.getLogger("ThreatMoni.NLPEngine")

class NLPEngine:
    """
    Practical Cybersecurity NLP & Entity Extraction Engine.
    Combines high-precision regex matching for structured security indicators,
    NLTK / spaCy tokenization, TF-IDF text feature extraction, and security keyword analysis.
    """

    def __init__(self):
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.hash_pattern = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
        self.mitre_pattern = re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.IGNORECASE)
        self.domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')

        self.security_keywords = set([
            "phishing", "malware", "ransomware", "ddos", "vulnerability", "exploit",
            "botnet", "credential", "trojan", "backdoor", "spyware", "keylogger",
            "exfiltration", "zero-day", "privilege", "escalation", "injection",
            "bypass", "overflow", "spoofing", "intercept", "quarantine", "patch"
        ])

        self.spacy_nlp = None
        self._init_spacy_safely()

    def _init_spacy_safely(self):
        try:
            import spacy
            self.spacy_nlp = spacy.load("en_core_web_sm")
            logger.info("Successfully loaded spaCy 'en_core_web_sm' model.")
        except Exception as e:
            logger.warning(f"spaCy model unavailable ({e}). Using regex + NLTK fallback engine.")
            self.spacy_nlp = None

    def extract_indicators_from_text(self, text: str) -> Dict[str, List[str]]:
        if not isinstance(text, str):
            text = str(text)

        cves = list(set(self.cve_pattern.findall(text)))
        ips = list(set(self.ip_pattern.findall(text)))
        hashes = list(set(self.hash_pattern.findall(text)))
        mitre_ids = list(set(self.mitre_pattern.findall(text)))
        
        words = set(re.findall(r'\b[a-zA-Z0-9_-]+\b', text.lower()))
        matched_sec_keywords = list(words.intersection(self.security_keywords))

        spacy_orgs, spacy_gpe, spacy_products = [], [], []
        if self.spacy_nlp:
            try:
                doc = self.spacy_nlp(text)
                for ent in doc.ents:
                    if ent.label_ == "ORG":
                        spacy_orgs.append(ent.text)
                    elif ent.label_ in ["GPE", "LOC"]:
                        spacy_gpe.append(ent.text)
                    elif ent.label_ in ["PRODUCT", "LAW"]:
                        spacy_products.append(ent.text)
            except Exception:
                pass

        return {
            "cves": cves,
            "ips": ips,
            "hashes": hashes,
            "mitre_techniques": mitre_ids,
            "security_keywords": matched_sec_keywords,
            "orgs": list(set(spacy_orgs)),
            "locations": list(set(spacy_gpe)),
            "products": list(set(spacy_products))
        }

    def process_dataframe(self, df: pd.DataFrame, text_col: str = "Cleaned Threat Description") -> pd.DataFrame:
        df_nlp = df.copy()

        cve_counts, ip_counts, hash_counts, technique_counts = [], [], [], []
        keyword_counts, total_ioc_counts = [], []

        for _, row in df_nlp.iterrows():
            text_val = row.get(text_col, "")
            ioc_val = row.get("IOCs (Indicators of Compromise)", "")
            
            combined_text = f"{text_val} {ioc_val}"
            extracted = self.extract_indicators_from_text(combined_text)

            cve_c = len(extracted["cves"])
            ip_c = len(extracted["ips"])
            hash_c = len(extracted["hashes"])
            tech_c = len(extracted["mitre_techniques"])
            kw_c = len(extracted["security_keywords"])
            
            # Count IOCs from IOC column or text
            ioc_list_count = 0
            if isinstance(ioc_val, str) and ioc_val.strip():
                items = [x.strip() for x in re.split(r"[,\[\]']", ioc_val) if x.strip()]
                ioc_list_count = len(items)

            cve_counts.append(cve_c)
            ip_counts.append(ip_c)
            hash_counts.append(hash_c)
            technique_counts.append(tech_c)
            keyword_counts.append(kw_c)
            total_ioc_counts.append(max(ioc_list_count, ip_c + hash_c))

        df_nlp["cve_count"] = cve_counts
        df_nlp["ip_count"] = ip_counts
        df_nlp["hash_count"] = hash_counts
        df_nlp["technique_count"] = technique_counts
        df_nlp["security_keyword_count"] = keyword_counts
        df_nlp["ioc_count"] = total_ioc_counts

        # Derive malware_count and actor_count from dataset fields where present
        if "Threat Actor" in df_nlp.columns:
            df_nlp["actor_count"] = df_nlp["Threat Actor"].apply(lambda a: 0 if str(a).lower() in ["unknown", "none", "nan"] else 1)
        else:
            df_nlp["actor_count"] = 0

        if "Threat Category" in df_nlp.columns:
            df_nlp["malware_count"] = df_nlp["Threat Category"].apply(lambda c: 1 if "malware" in str(c).lower() or "ransomware" in str(c).lower() else 0)
        else:
            df_nlp["malware_count"] = 0

        df_nlp["vulnerability_count"] = df_nlp["cve_count"]

        logger.info("Completed NLP entity extraction and feature count calculation.")
        return df_nlp

    def compute_tfidf_features(self, df: pd.DataFrame, text_col: str = "Cleaned Threat Description", max_features: int = 20) -> pd.DataFrame:
        corpus = df[text_col].fillna("").astype(str).tolist()
        tfidf = TfidfVectorizer(max_features=max_features, stop_words='english')
        tfidf_matrix = tfidf.fit_transform(corpus)
        
        feature_names = [f"tfidf_{name}" for name in tfidf.get_feature_names_out()]
        tfidf_df = pd.DataFrame(tfidf_matrix.toarray(), columns=feature_names, index=df.index)
        return tfidf_df
