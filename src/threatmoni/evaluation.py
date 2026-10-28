import os
import pandas as pd
import numpy as np
import logging
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

logger = logging.getLogger("ThreatMoni.Evaluation")

class ModelEvaluator:
    """
    Evaluates trained machine learning models, outputs comparative performance tables,
    and generates visual graphs (confusion matrices, accuracy/F1 comparisons, feature importances).
    """

    def __init__(self, tables_dir: str = "outputs/tables", figures_dir: str = "outputs/figures"):
        self.tables_dir = tables_dir
        self.figures_dir = figures_dir
        os.makedirs(self.tables_dir, exist_ok=True)
        os.makedirs(self.figures_dir, exist_ok=True)

    def evaluate_all(self, trained_results: dict) -> pd.DataFrame:
        metrics_list = []

        for name, res in trained_results.items():
            y_test = res["y_test"]
            y_pred = res["y_pred"]
            class_names = res["class_names"]

            acc = accuracy_score(y_test, y_pred)
            prec_macro = precision_score(y_test, y_pred, average="macro", zero_division=0)
            prec_weighted = precision_score(y_test, y_pred, average="weighted", zero_division=0)
            rec_macro = recall_score(y_test, y_pred, average="macro", zero_division=0)
            rec_weighted = recall_score(y_test, y_pred, average="weighted", zero_division=0)
            f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
            f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)

            metrics_list.append({
                "Model": name,
                "Accuracy": round(acc, 4),
                "Precision (Macro)": round(prec_macro, 4),
                "Precision (Weighted)": round(prec_weighted, 4),
                "Recall (Macro)": round(rec_macro, 4),
                "Recall (Weighted)": round(rec_weighted, 4),
                "F1 Score (Macro)": round(f1_macro, 4),
                "F1 Score (Weighted)": round(f1_weighted, 4)
            })

            # Plot Confusion Matrix
            cm = confusion_matrix(y_test, y_pred)
            self._plot_confusion_matrix(cm, class_names, name)

        comparison_df = pd.DataFrame(metrics_list).sort_values(by="F1 Score (Weighted)", ascending=False)
        
        # Save comparison table
        table_path = os.path.join(self.tables_dir, "model_comparison.csv")
        comparison_df.to_csv(table_path, index=False)
        logger.info(f"Saved model evaluation comparison table to '{table_path}'.")

        # Plot Comparative Bar Charts
        self._plot_model_comparison_charts(comparison_df)
        
        # Feature Importance for Random Forest / XGBoost
        self._plot_feature_importance(trained_results)

        return comparison_df

    def _plot_confusion_matrix(self, cm: np.ndarray, class_names: list, model_name: str):
        plt.figure(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=class_names, yticklabels=class_names)
        plt.title(f"Confusion Matrix - {model_name}")
        plt.xlabel("Predicted Class")
        plt.ylabel("True Class")
        plt.tight_layout()
        
        fname = f"confusion_matrix_{model_name.lower().replace(' ', '_')}.png"
        plt.savefig(os.path.join(self.figures_dir, fname), dpi=300)
        plt.close()

    def _plot_model_comparison_charts(self, df: pd.DataFrame):
        metrics = [
            ("Accuracy", "model_accuracy.png"),
            ("Precision (Macro)", "model_precision.png"),
            ("Recall (Macro)", "model_recall.png"),
            ("F1 Score (Macro)", "model_f1.png")
        ]

        for col, fname in metrics:
            plt.figure(figsize=(9, 5))
            sns.barplot(data=df, x="Model", y=col, palette="viridis")
            plt.title(f"ThreatMoni Classification - {col}")
            plt.ylim(0, 1.05)
            plt.xticks(rotation=25)
            for index, row in df.iterrows():
                plt.text(index, row[col] + 0.02, f"{row[col]:.3f}", ha='center', fontsize=9)
            plt.tight_layout()
            plt.savefig(os.path.join(self.figures_dir, fname), dpi=300)
            plt.close()

    def _plot_feature_importance(self, trained_results: dict):
        for name in ["Random Forest", "XGBoost"]:
            if name in trained_results:
                res = trained_results[name]
                model = res["model"]
                feature_names = res["feature_names"]

                if hasattr(model, "feature_importances_"):
                    importances = model.feature_importances_
                    fi_df = pd.DataFrame({
                        "Feature": feature_names,
                        "Importance": importances
                    }).sort_values(by="Importance", ascending=False).head(10)

                    plt.figure(figsize=(8, 5))
                    sns.barplot(data=fi_df, x="Importance", y="Feature", palette="magma")
                    plt.title(f"Top 10 Feature Importances - {name}")
                    plt.tight_layout()
                    
                    fname = f"feature_importance_{name.lower().replace(' ', '_')}.png"
                    plt.savefig(os.path.join(self.figures_dir, fname), dpi=300)
                    plt.close()
