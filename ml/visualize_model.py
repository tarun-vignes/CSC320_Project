import json
import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

MODEL_PATH  = os.path.join("models", "model_params.json")
OUTPUT_DIR  = "results"

def load_params():
    with open(MODEL_PATH, "r") as f:
        return json.load(f)

def plot_feature_importance(params, ax):
    features = params["feature_columns"]
    importances = [params["coefficients"][f] for f in features]

    labels = [
        "File Size", "Entropy", "Keyword Count",
        "API Hit Count", "MZ Header", "Has URL", "Has Network"
    ]

    sorted_pairs = sorted(zip(importances, labels), reverse=True)
    importances_sorted, labels_sorted = zip(*sorted_pairs)

    colors = ["#C0392B" if v > 0.1 else "#2980B9" for v in importances_sorted]

    bars = ax.barh(labels_sorted, importances_sorted, color=colors, edgecolor="none", height=0.6)
    ax.set_xlabel("Feature Importance (RF coefficient)", fontsize=11)
    ax.set_title("Feature Importances", fontsize=13, fontweight="bold")
    ax.invert_yaxis()
    ax.set_xlim(0, max(importances_sorted) * 1.25)

    for bar, val in zip(bars, importances_sorted):
        ax.text(val + 0.003, bar.get_y() + bar.get_height() / 2,
                f"{val:.4f}", va="center", fontsize=9)

    high_patch = mpatches.Patch(color="#C0392B", label="High importance (> 0.10)")
    low_patch  = mpatches.Patch(color="#2980B9", label="Lower importance")
    ax.legend(handles=[high_patch, low_patch], fontsize=9, loc="lower right")
    ax.grid(axis="x", linestyle="--", alpha=0.4)
    ax.set_facecolor("#F9F9F9")

def plot_feature_means(params, ax):
    features = params["feature_columns"]
    means = [params["feature_means"][f] for f in features]
    stds  = [params["feature_stds"][f]  for f in features]

    labels = [
        "File Size", "Entropy", "Keyword\nCount",
        "API Hits", "MZ Header", "Has URL", "Has Network"
    ]

    # Normalize for display so file_size doesn't dwarf everything
    means_norm = [m / (s if s > 0 else 1) for m, s in zip(means, stds)]

    x = np.arange(len(labels))
    bars = ax.bar(x, means_norm, color="#2471A3", edgecolor="none", width=0.55)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylabel("Normalized mean (mean / std)", fontsize=10)
    ax.set_title("Feature Distributions (Training Set)", fontsize=13, fontweight="bold")
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_facecolor("#F9F9F9")

    for bar, raw_mean in zip(bars, means):
        label = f"{raw_mean:.2f}" if raw_mean < 100 else f"{raw_mean:,.0f}"
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                label, ha="center", va="bottom", fontsize=8)

def plot_logistic_curve(params, ax):
    rf_intercept   = params["rf_intercept"]
    rf_coefficient = params["rf_coefficient"]

    x = np.linspace(0, 1, 300)
    z = rf_intercept + rf_coefficient * x
    prob = 1 / (1 + np.exp(-z))

    ax.plot(x, prob, color="#C0392B", linewidth=2.5, label="Calibrated probability")
    ax.axhline(0.5, color="gray", linestyle="--", linewidth=1, label="Decision threshold (0.5)")
    ax.axvline(x[np.argmin(np.abs(prob - 0.5))], color="#117A65",
               linestyle=":", linewidth=1.5, label="RF score at threshold")

    ax.fill_between(x, prob, 0.5, where=(prob >= 0.5), alpha=0.12, color="#C0392B", label="Malware region")
    ax.fill_between(x, prob, 0.5, where=(prob < 0.5),  alpha=0.12, color="#2980B9", label="Benign region")

    ax.set_xlabel("Random Forest vote probability", fontsize=11)
    ax.set_ylabel("Calibrated malware probability", fontsize=11)
    ax.set_title("Logistic Calibration Curve", fontsize=13, fontweight="bold")
    ax.legend(fontsize=9)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.grid(linestyle="--", alpha=0.4)
    ax.set_facecolor("#F9F9F9")

def main():
    if not os.path.exists(MODEL_PATH):
        print(f"Error: {MODEL_PATH} not found. Run train_model.py first.")
        return

    params = load_params()
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    fig.suptitle("ML Model Analysis — Static Malware Scanner", fontsize=15, fontweight="bold", y=1.01)

    plot_feature_importance(params, axes[0])
    plot_feature_means(params, axes[1])
    plot_logistic_curve(params, axes[2])

    plt.tight_layout()
    out_path = os.path.join(OUTPUT_DIR, "ml_analysis.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"Saved: {out_path}")
    plt.show()

if __name__ == "__main__":
    main()