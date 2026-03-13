#include "rule_engine.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    DetectionResult result;
    Features features;

    /* Build a clearly suspicious feature set that should cross the default threshold. */
    memset(&features, 0, sizeof(features));
    features.file_size = 1024;
    features.entropy = 7.5;
    features.keyword_count = 6;
    features.api_hit_count = 1;
    features.has_mz_header = 1;
    features.has_url = 1;

    if (score_features(&features, &result, DEFAULT_THRESHOLD) <= 0) {
        fprintf(stderr, "Expected positive score.\n");
        return 1;
    }

    if (!result.is_malware) {
        fprintf(stderr, "Expected malware classification.\n");
        return 1;
    }

    /* This test is intentionally small: it proves the rule engine is wired correctly. */
    printf("smoke test passed: score=%d rules=%d\n", result.score, result.rule_count);
    return 0;
}
