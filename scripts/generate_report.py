import sys
import os
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from threatmoni.threat_scoring import ThreatScorer
from threatmoni.entity_extraction import EntityExtractor
from threatmoni.horizon_scanning import HorizonScanner
from threatmoni.reporting import ReportGenerator

def generate_reports():
    feats_path = "data/processed/threatmoni_features.csv"
    if not os.path.exists(feats_path):
        print("Error: Features dataset missing. Run scripts/prepare_data.py first.")
        sys.exit(1)

    print("[1/3] Calculating ThreatMoni scores (SCS, TFS, IQ, TCS, TRS, TPI)...")
    df_features = pd.read_csv(feats_path)
    scorer = ThreatScorer(outputs_dir="outputs")
    df_scored = scorer.calculate_all_scores(df_features)

    print("[2/3] Performing Horizon Scanning analysis...")
    scanner = HorizonScanner(tables_dir="outputs/tables")
    horizon_results = scanner.scan_horizon(df_scored)

    print("[3/3] Exporting research reports & Excel workbook...")
    extractor = EntityExtractor()
    entity_summary = extractor.summarize_entities(df_scored)

    reporter = ReportGenerator(outputs_dir="outputs")
    comp_path = "outputs/tables/model_comparison.csv"
    model_comp = pd.read_csv(comp_path) if os.path.exists(comp_path) else pd.DataFrame()

    tables_dict = {
        "Threat_Scores": df_scored[["scs_score", "tfs_score", "iq_score", "tcs_score", "trs_score", "tpi_score", "threat_priority"]].head(100),
        "Threat_Priority": horizon_results["priority_distribution"],
        "Top_Threats": horizon_results["top_threats_summary"]
    }
    reporter.generate_excel_workbook(tables_dict)
    reporter.generate_final_report(df_scored, model_comp, entity_summary)
    reporter.generate_paper_ready_results(df_scored, model_comp)
    print("Report generation complete!")

if __name__ == "__main__":
    generate_reports()
