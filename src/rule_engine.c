#include "rule_engine.h"

/* Weighted rule set for baseline static classification. */
DetectionResult run_rules(const Features *features, int threshold) {
    DetectionResult result;
    result.score = 0;
    result.triggered_entropy = 0;
    result.triggered_strings = 0;
    result.triggered_imports = 0;
    result.triggered_header = 0;

    if (features == NULL) {
        return result;
    }

    if (features->byte_entropy >= 7.20) {
        result.score += 35;
        result.triggered_entropy = 1;
    }

    if (features->suspicious_string_hits >= 2) {
        result.score += 35;
        result.triggered_strings = 1;
    } else if (features->suspicious_string_hits == 1) {
        result.score += 15;
    }

    if (features->suspicious_import_hits >= 2) {
        result.score += 20;
        result.triggered_imports = 1;
    }

    if (features->has_mz_header) {
        result.score += 10;
        result.triggered_header = 1;
    }

    if (result.score < 0) {
        result.score = 0;
    }
    if (result.score > 100) {
        result.score = 100;
    }

    /* Kept in signature for future threshold-aware calibration logic. */
    (void)threshold;
    return result;
}
