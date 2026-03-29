import sys
import json
import math
import os

# Default fallback values if no trained model is found
DEFAULT_PARAMS = {
    "intercept": -8.20,
    "coefficients": {
        "file_size": 0.000001,
        "byte_entropy": 1.35,
        "suspicious_string_hits": 0.85,
        "suspicious_import_hits": 0.95,
        "has_mz_header": 0.70,
    }
}

def sigmoid(z):
    return 1.0 / (1.0 + math.exp(-z))

def load_params():
    """
    Loads trained model parameters if model_params.json exists.
    Otherwise uses default placeholder values.
    """
    model_path = os.path.join("models", "model_params.json")
    if os.path.exists(model_path):
        with open(model_path, "r") as f:
            return json.load(f)
    return DEFAULT_PARAMS

def main():
    # Expecting 5 features from C
    if len(sys.argv) != 6:
        print(json.dumps({
            "probability": 0.0,
            "label": 0
        }))
        return

    file_size = float(sys.argv[1])
    entropy = float(sys.argv[2])
    suspicious_strings = float(sys.argv[3])
    suspicious_imports = float(sys.argv[4])
    has_mz = float(sys.argv[5])

    params = load_params()
    intercept = params["intercept"]
    coefs = params["coefficients"]

    # Logistic regression formula
    z = (
        intercept
        + coefs["file_size"] * file_size
        + coefs["byte_entropy"] * entropy
        + coefs["suspicious_string_hits"] * suspicious_strings
        + coefs["suspicious_import_hits"] * suspicious_imports
        + coefs["has_mz_header"] * has_mz
    )

    probability = sigmoid(z)
    label = 1 if probability >= 0.5 else 0

    print(json.dumps({
        "probability": probability,
        "label": label
    }))

if __name__ == "__main__":
    main()