import os
import pandas as pd
import numpy as np
import logging
import matplotlib.pyplot as plt
import seaborn as sns

logger = logging.getLogger("ThreatMoni.Visualization")

class Visualizer:
    """
    Generates high-resolution, publication-quality research figures for ThreatMoni.
    Saved under outputs/figures/.
    """

    def __init__(self, figures_dir: str = "outputs/figures"):
        self.figures_dir = figures_dir
        os.makedirs(self.figures_dir, exist_ok=True)
        sns.set_theme(style="whitegrid", font="sans-serif")

    def generate_all_figures(self, df: pd.DataFrame):
        self.plot_class_distribution(df)
        self.plot_threat_category_distribution(df)
        self.plot_threat_priority_distribution(df)
        self.plot_tpi_distribution(df)
        self.plot_attack_vector_frequency(df)
        self.plot_geographical_distribution(df)
        self.plot_threat_actor_frequency(df)
        self.plot_severity_vs_tpi(df)
        self.plot_emerging_threats(df)
        self.plot_risk_level_distribution(df)
        logger.info("Generated all ThreatMoni research figures.")

    def plot_class_distribution(self, df: pd.DataFrame):
        plt.figure(figsize=(7, 4.5))
        ax = sns.countplot(data=df, x="Threat Category", palette="Blues_r")
        plt.title("Figure 1: Dataset Target Class Distribution")
        plt.xlabel("Threat Category")
        plt.ylabel("Number of Records")
        for p in ax.patches:
            ax.annotate(f"{int(p.get_height())}", (p.get_x() + p.get_width() / 2., p.get_height()),
                        ha='center', va='center', xytext=(0, 5), textcoords='offset points', fontsize=10)
        plt.tight_layout()
        plt.savefig(os.path.join(self.figures_dir, "class_distribution.png"), dpi=300)
        plt.close()

    def plot_threat_category_distribution(self, df: pd.DataFrame):
        plt.figure(figsize=(7, 4.5))
        counts = df["Threat Category"].value_counts()
        plt.pie(counts.values, labels=counts.index, autopct='%1.1f%%', colors=sns.color_palette("mako", len(counts)))
        plt.title("Figure 2: Threat Category Percentage Breakdown")
        plt.tight_layout()
        plt.savefig(os.path.join(self.figures_dir, "threat_category_distribution.png"), dpi=300)
        plt.close()

    def plot_threat_priority_distribution(self, df: pd.DataFrame):
        plt.figure(figsize=(7, 4.5))
        palette = {"Low": "#2ecc71", "Medium": "#f39c12", "High": "#e67e22", "Critical": "#e74c3c"}
        ax = sns.countplot(data=df, x="threat_priority", order=["Low", "Medium", "High", "Critical"], palette=palette)
        plt.title("Figure 3: Threat Priority Level Distribution")
        plt.xlabel("Threat Priority (TPI Level)")
        plt.ylabel("Record Count")
        for p in ax.patches:
            height = p.get_height()
            if not np.isnan(height) and height > 0:
                ax.annotate(f"{int(height)}", (p.get_x() + p.get_width() / 2., height),
                            ha='center', va='center', xytext=(0, 5), textcoords='offset points', fontsize=10)
        plt.tight_layout()
        plt.savefig(os.path.join(self.figures_dir, "threat_priority_distribution.png"), dpi=300)
        plt.close()

    def plot_tpi_distribution(self, df: pd.DataFrame):
        plt.figure(figsize=(8, 4.5))
        sns.histplot(df["tpi_score"], kde=True, color="#3498db", bins=20)
        plt.axvline(25, color='#2ecc71', linestyle='--', label='Low/Medium Threshold (25)')
        plt.axvline(50, color='#f39c12', linestyle='--', label='Medium/High Threshold (50)')
        plt.axvline(75, color='#e74c3c', linestyle='--', label='High/Critical Threshold (75)')
        plt.title("Figure 4: Threat Priority Index (TPI) Continuous Score Distribution")
        plt.xlabel("TPI Score (0 - 100)")
        plt.ylabel("Frequency")
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(self.figures_dir, "tpi_distribution.png"), dpi=300)
        plt.close()

    def plot_attack_vector_frequency(self, df: pd.DataFrame):
        if "Attack Vector" in df.columns:
            plt.figure(figsize=(7, 4.5))
            ax = sns.countplot(data=df, x="Attack Vector", palette="magma")
            plt.title("Figure 5: Attack Vector Frequency")
            plt.xlabel("Attack Vector")
            plt.ylabel("Count")
            for p in ax.patches:
                ax.annotate(f"{int(p.get_height())}", (p.get_x() + p.get_width() / 2., p.get_height()),
                            ha='center', va='center', xytext=(0, 5), textcoords='offset points')
            plt.tight_layout()
            plt.savefig(os.path.join(self.figures_dir, "attack_vector_frequency.png"), dpi=300)
            plt.close()

    def plot_geographical_distribution(self, df: pd.DataFrame):
        if "Geographical Location" in df.columns:
            plt.figure(figsize=(8, 4.5))
            counts = df["Geographical Location"].value_counts()
            sns.barplot(x=counts.values, y=counts.index, palette="viridis")
            plt.title("Figure 6: Geographical Threat Origin Distribution")
            plt.xlabel("Record Count")
            plt.ylabel("Location")
            plt.tight_layout()
            plt.savefig(os.path.join(self.figures_dir, "geographical_distribution.png"), dpi=300)
            plt.close()

    def plot_threat_actor_frequency(self, df: pd.DataFrame):
        if "Threat Actor" in df.columns:
            plt.figure(figsize=(7, 4.5))
            counts = df["Threat Actor"].value_counts()
            sns.barplot(x=counts.index, y=counts.values, palette="rocket")
            plt.title("Figure 7: Threat Actor Frequency")
            plt.xlabel("Threat Actor")
            plt.ylabel("Count")
            plt.xticks(rotation=20)
            plt.tight_layout()
            plt.savefig(os.path.join(self.figures_dir, "threat_actor_frequency.png"), dpi=300)
            plt.close()

    def plot_severity_vs_tpi(self, df: pd.DataFrame):
        if "Severity Score" in df.columns:
            plt.figure(figsize=(8, 5))
            sns.boxplot(data=df, x="Severity Score", y="tpi_score", palette="coolwarm")
            plt.title("Figure 8: TPI Score vs Raw Severity Score")
            plt.xlabel("Severity Score (Raw)")
            plt.ylabel("Calculated TPI Score")
            plt.tight_layout()
            plt.savefig(os.path.join(self.figures_dir, "severity_vs_tpi.png"), dpi=300)
            plt.close()

    def plot_emerging_threats(self, df: pd.DataFrame):
        plt.figure(figsize=(8, 5))
        top_cats = df.groupby("Threat Category")["tpi_score"].mean().sort_values(ascending=False)
        sns.barplot(x=top_cats.values, y=top_cats.index, palette="flare")
        plt.title("Figure 9: Threat Categories Ranked by Mean TPI Priority")
        plt.xlabel("Mean TPI Score")
        plt.ylabel("Threat Category")
        plt.tight_layout()
        plt.savefig(os.path.join(self.figures_dir, "emerging_threats.png"), dpi=300)
        plt.close()

    def plot_risk_level_distribution(self, df: pd.DataFrame):
        if "Risk Level Prediction" in df.columns:
            plt.figure(figsize=(7, 4.5))
            sns.histplot(df["Risk Level Prediction"], bins=5, color="#8e44ad")
            plt.title("Figure 10: Original Risk Level Prediction Distribution")
            plt.xlabel("Risk Level Prediction (Raw)")
            plt.ylabel("Frequency")
            plt.tight_layout()
            plt.savefig(os.path.join(self.figures_dir, "risk_level_distribution.png"), dpi=300)
            plt.close()
