import sys
import json
import math
import os

# Fallback parameters if no trained model exists yet.
# Coefficients are feature importances approximated from heuristic weights.
DEFAULT_PARAMS = {
    "intercept": -3.50,
    "coefficients": {
        "file_size":      0.000001,
        "entropy":        1.20,
        "keyword_count":  0.80,
        "api_hit_count":  0.95,
        "has_mz_header":  0.70,
        "has_url":        0.60,
        "has_network":    0.65
    }
}

MODEL_PATH = os.path.join("../models", "model_params.json")

def sigmoid(z):
    # Clamp z to avoid overflow in math.exp
    z = max(-500.0, min(500.0, z))
    return 1.0 / (1.0 + math.exp(-z))

def load_params():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "r") as f:
            return json.load(f)
    return DEFAULT_PARAMS

def main():
    # C bridge sends exactly 7 features matching FEATURE_COLUMNS order:
    # file_size, entropy, keyword_count, api_hit_count,
    # has_mz_header, has_url, has_network
    if len(sys.argv) != 8:
        print(json.dumps({"probability": 0.0, "label": 0}))
        return

    features = {
        "file_size":      float(sys.argv[1]),
        "entropy":        float(sys.argv[2]),
        "keyword_count":  float(sys.argv[3]),
        "api_hit_count":  float(sys.argv[4]),
        "has_mz_header":  float(sys.argv[5]),
        "has_url":        float(sys.argv[6]),
        "has_network":    float(sys.argv[7])
    }

    params = load_params()
    intercept = params["intercept"]
    coefs     = params["coefficients"]

    z = intercept + sum(coefs[k] * features[k] for k in features)

    probability = sigmoid(z)
    label = 1 if probability >= 0.5 else 0

    print(json.dumps({"probability": round(probability, 6), "label": label}))

if __name__ == "__main__":
    main()
