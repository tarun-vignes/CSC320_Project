import json
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

DATASET_PATH = os.path.join("../dataset", "features.csv")
MODEL_OUTPUT = os.path.join("../models", "model_params.json")

# Must match columns written by dataset_exporter.c
FEATURE_COLUMNS = [
    "file_size",
    "entropy",
    "keyword_count",
    "api_hit_count",
    "has_mz_header",
    "has_url",
    "has_network"
]


def main():
    if not os.path.exists(DATASET_PATH):
        print(f"Error: dataset not found at {DATASET_PATH}")
        print("Run build_dataset first to generate it.")
        return

    df = pd.read_csv(DATASET_PATH)

    missing = [c for c in FEATURE_COLUMNS + ["label"] if c not in df.columns]
    if missing:
        print(f"Error: CSV is missing columns: {missing}")
        return

    if len(df) < 10:
        print(f"Error: only {len(df)} rows found — need more samples before training.")
        return

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    print(f"Dataset loaded: {len(df)} samples ({y.sum()} malicious, {(y == 0).sum()} benign)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]

    print("\nModel Evaluation")
    print("----------------")
    print(f"Accuracy  : {accuracy_score(y_test, predictions):.4f}")
    print(f"Precision : {precision_score(y_test, predictions, zero_division=0):.4f}")
    print(f"Recall    : {recall_score(y_test, predictions, zero_division=0):.4f}")
    print(f"F1 Score  : {f1_score(y_test, predictions, zero_division=0):.4f}")

    tn, fp, fn, tp = confusion_matrix(y_test, predictions).ravel()
    print(f"\nConfusion Matrix")
    print(f"  TP={tp}  FP={fp}")
    print(f"  FN={fn}  TN={tn}")

    print("\nClassification Report")
    print("---------------------")
    print(classification_report(y_test, predictions, zero_division=0))

    print("Feature Importances")
    print("-------------------")
    for name, importance in zip(FEATURE_COLUMNS, model.feature_importances_):
        print(f"  {name:<25} {importance:.4f}")

    # Save thresholds and tree vote counts per class for use by ml_runner.py
    # Random Forest doesn't have linear coefficients, so we serialize the
    # per-tree vote structure as a probability lookup via the training set.
    # ml_runner.py uses a lightweight logistic approximation trained on the
    # RF probability outputs so the C bridge stays simple (no sklearn at runtime).
    from sklearn.linear_model import LogisticRegression
    import numpy as np

    rf_probs_train = model.predict_proba(X_train)[:, 1]
    lr_calibrator  = LogisticRegression(max_iter=1000)
    lr_calibrator.fit(rf_probs_train.reshape(-1, 1), y_train)

    # Save both the RF feature weights (importances) and the LR calibration
    # so ml_runner.py can do a fast dot-product without importing sklearn.
    params = {
        "intercept": float(lr_calibrator.intercept_[0]),
        "feature_means": {col: float(X_train[col].mean()) for col in FEATURE_COLUMNS},
        "feature_stds":  {col: float(max(X_train[col].std(), 1e-9)) for col in FEATURE_COLUMNS},
        "coefficients": {
            col: float(imp)
            for col, imp in zip(FEATURE_COLUMNS, model.feature_importances_)
        },
        "rf_intercept":   float(lr_calibrator.intercept_[0]),
        "rf_coefficient": float(lr_calibrator.coef_[0][0]),
        "feature_columns": FEATURE_COLUMNS
    }

    os.makedirs("../models", exist_ok=True)
    with open(MODEL_OUTPUT, "w") as f:
        json.dump(params, f, indent=4)

    print(f"\nSaved model parameters to {MODEL_OUTPUT}")


if __name__ == "__main__":
    main()