#include "rule_engine.h"

#include "utils.h"

/* Keeps the final score inside the public 0-100 range. */
static int clamp_score(int score) {
    if (score < 0) {
        return 0;
    }
    if (score > 100) {
        return 100;
    }
    return score;
}

int score_features(const Features *features, DetectionResult *result, int threshold) {
    int score = 0;

    if (features == NULL || result == NULL) {
        return -1;
    }

    reset_detection_result(result, threshold);

    /* Entropy is a rough signal for packing, encryption, or obfuscation. */
    if (features->entropy > 7.0) {
        score += 20;
        log_rule(result, "HIGH_ENTROPY", 20);
    } else if (features->entropy > 6.0) {
        score += 10;
        log_rule(result, "MED_ENTROPY", 10);
    }

    /* Keyword volume captures suspicious intent exposed in embedded strings. */
    if (features->keyword_count > 5) {
        score += 15;
        log_rule(result, "MANY_KEYWORDS", 15);
    } else if (features->keyword_count > 2) {
        score += 7;
        log_rule(result, "SOME_KEYWORDS", 7);
    }

    /* Dangerous APIs often point to injection or execution behavior. */
    if (features->api_hit_count > 0) {
        score += 20;
        log_rule(result, "DANGEROUS_API", 20);
    }

    /* Executable-looking files receive extra weight. */
    if (features->has_mz_header) {
        score += 15;
        log_rule(result, "MZ_HEADER", 15);
    }

    /* Embedded destinations and network code raise the risk score further. */
    if (features->has_url) {
        score += 10;
        log_rule(result, "EMBEDDED_URL", 10);
    }

    if (features->has_network) {
        score += 10;
        log_rule(result, "NETWORK_CODE", 10);
    }

    result->score = clamp_score(score);
    result->is_malware = (result->score >= threshold);
    return result->score;
}
