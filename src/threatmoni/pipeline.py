import os
import logging
import pandas as pd

from .data_loader import DataLoader
from .profiler import DatasetProfiler
from .preprocessing import DataPreprocessor
from .nlp_engine import NLPEngine
from .entity_extraction import EntityExtractor
from .feature_engineering import FeatureEngineer
from .threat_scoring import ThreatScorer
from .model_training import ThreatClassifier
from .evaluation import ModelEvaluator
from .horizon_scanning import HorizonScanner
from .visualization import Visualizer
from .reporting import ReportGenerator

logger = logging.getLogger("ThreatMoni.Pipeline")

class ThreatMoniPipeline:
    """
    Complete end-to-end orchestration pipeline for ThreatMoni framework.
    Executes all 18 processing, scoring, ML, visualization, and reporting steps.
    """

    def __init__(self, raw_dir: str = "data/raw", outputs_dir: str = "outputs"):
        self.raw_dir = raw_dir
        self.outputs_dir = outputs_dir

        self.loader = DataLoader(raw_dir=raw_dir)
        self.profiler = DatasetProfiler(output_dir=outputs_dir)
        self.preprocessor = DataPreprocessor(processed_dir="data/processed", outputs_dir=outputs_dir)
        self.entity_extractor = EntityExtractor()
        self.feature_engineer = FeatureEngineer(processed_dir="data/processed")
        self.scorer = ThreatScorer(outputs_dir=outputs_dir)
        self.classifier = ThreatClassifier(models_dir=os.path.join(outputs_dir, "models"))
        self.evaluator = ModelEvaluator(tables_dir=os.path.join(outputs_dir, "tables"), figures_dir=os.path.join(outputs_dir, "figures"))
        self.horizon_scanner = HorizonScanner(tables_dir=os.path.join(outputs_dir, "tables"))
        self.visualizer = Visualizer(figures_dir=os.path.join(outputs_dir, "figures"))
        self.reporter = ReportGenerator(outputs_dir=outputs_dir)

    def run(self):
        print("=" * 60)
        print(" ThreatMoni: OSINT Web Mining Framework for Horizon Scanning ")
        print("=" * 60)

        print("[1/18] Dataset discovery...")
        self.loader.discover_datasets()
        df_raw = self.loader.load_primary_dataset()

        print("[2/18] Profiling dataset schema and semantics...")
        profile = self.profiler.profile_dataset(df_raw)

        print("[3/18] Preprocessing and cybersecurity indicator preservation...")
        df_clean = self.preprocessor.preprocess(df_raw)

        print("[4/18] Performing NLP extraction...")
        # Entity extraction handled in preprocessing/features

        print("[5/18] Feature engineering (NLP, text metrics, statistical proxies)...")
        df_features = self.feature_engineer.build_features(df_clean)

        print("[6/18] Calculating Source Credibility Score (SCS = (R+U+C+A)/4)...")
        print("[7/18] Calculating Threat Frequency Score (TFS = Nt/N)...")
        print("[8/18] Calculating Intelligence Quality (IQ)...")
        print("[9/18] Calculating Threat Confidence Score (TCS = alpha(SCS) + beta(IQ))...")
        print("[10/18] Calculating Threat Risk Score (TRS = Sum(Wi * Fi))...")
        print("[11/18] Calculating Threat Priority Index (TPI = (TRS * TCS)/100) & Priority Levels...")
        df_scored = self.scorer.calculate_all_scores(df_features)

        print("[12/18] Training Machine Learning Classifiers (6 Models)...")
        trained_results = self.classifier.train_all_models(df_scored, target_col="Threat Category")

        print("[13/18] Evaluating ML Models & generating comparison metrics...")
        model_comp = self.evaluator.evaluate_all(trained_results)

        print("[14/18] Conducting Threat Horizon Scanning...")
        horizon_results = self.horizon_scanner.scan_horizon(df_scored)

        print("[15/18] Generating publication-quality figures...")
        self.visualizer.generate_all_figures(df_scored)

        print("[16/18] Compiling research tables (Tables 1-9)...")
        entity_summary = self.entity_extractor.summarize_entities(df_scored)
        entity_summary.to_csv(os.path.join(self.outputs_dir, "tables", "extracted_entities.csv"), index=False)

        tables_dict = {
            "Dataset_Profile": pd.DataFrame([profile]),
            "Preprocessing": pd.read_csv(os.path.join(self.outputs_dir, "data_profile.csv")),
            "Entities": entity_summary,
            "Threat_Scores": df_scored[["scs_score", "tfs_score", "iq_score", "tcs_score", "trs_score", "tpi_score", "threat_priority"]].head(100),
            "Threat_Priority": horizon_results["priority_distribution"],
            "Model_Performance": model_comp,
            "Top_Threats": horizon_results["top_threats_summary"]
        }

        print("[17/18] Exporting research results to Excel workbook...")
        self.reporter.generate_excel_workbook(tables_dict)

        print("[18/18] Generating final research reports and audits...")
        self.reporter.generate_leakage_check_doc(df_features)
        self.reporter.generate_reproducibility_json(profile, model_comp)
        self.reporter.generate_final_report(df_scored, model_comp, entity_summary)
        self.reporter.generate_paper_ready_results(df_scored, model_comp)

        print("=" * 60)
        print(" ThreatMoni Pipeline Execution Successfully Completed! ")
        print("=" * 60)
        return df_scored, model_comp
