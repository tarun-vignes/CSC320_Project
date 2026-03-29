import json
import os
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score

DATASET_PATH = os.path.join("dataset", "features.csv")
MODEL_OUTPUT_PATH = os.path.join("models", "model_params.json")

FEATURE_COLUMNS = [
    "file_size",
    "byte_entropy",
    "suspicious_string_hits",
    "suspicious_import_hits",
    "has_mz_header"
]

def main():
    # Make sure dataset exists
    if not os.path.exists(DATASET_PATH):
        print(f"Error: dataset not found at {DATASET_PATH}")
        return

    # Read dataset
    df = pd.read_csv(DATASET_PATH)

    # Make sure label column exists
    if "label" not in df.columns:
        print("Error: dataset must contain a 'label' column.")
        return

    # Separate features and labels
    X = df[FEATURE_COLUMNS]
    y = df["label"]

    # Need enough data to train
    if len(df) < 4:
        print("Error: need more dataset rows before training.")
        return

    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train logistic regression model
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    # Evaluate model
    predictions = model.predict(X_test)

    print("Model Evaluation")
    print("----------------")
    print("Accuracy :", accuracy_score(y_test, predictions))
    print("Precision:", precision_score(y_test, predictions, zero_division=0))
    print("Recall   :", recall_score(y_test, predictions, zero_division=0))
    print("F1 Score :", f1_score(y_test, predictions, zero_division=0))
    print("\nClassification Report")
    print("---------------------")
    print(classification_report(y_test, predictions, zero_division=0))

    # Save learned weights
    params = {
        "intercept": float(model.intercept_[0]),
        "coefficients": {
            "file_size": float(model.coef_[0][0]),
            "byte_entropy": float(model.coef_[0][1]),
            "suspicious_string_hits": float(model.coef_[0][2]),
            "suspicious_import_hits": float(model.coef_[0][3]),
            "has_mz_header": float(model.coef_[0][4])
        }
    }

    os.makedirs("models", exist_ok=True)

    with open(MODEL_OUTPUT_PATH, "w") as f:
        json.dump(params, f, indent=4)

    print(f"\nSaved trained parameters to {MODEL_OUTPUT_PATH}")

if __name__ == "__main__":
    main()