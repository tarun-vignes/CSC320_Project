#include "feature_extractor.h"
#include "rule_engine.h"
#include "python_ml_bridge.h"
#include "scanner_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Prints CLI usage. */
static void print_usage(const char *program_name) {
    printf("Usage: %s <path-to-file> [--threshold N]\n", program_name);
    printf("Example: %s sample.exe --threshold 70\n", program_name);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *file_path = argv[1];
    int threshold = DEFAULT_THRESHOLD;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--threshold") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --threshold requires a value.\n");
                return 1;
            }
            threshold = atoi(argv[++i]);
            if (threshold < 0 || threshold > 100) {
                fprintf(stderr, "Error: threshold must be between 0 and 100.\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Error: unknown argument '%s'.\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Extract static features using main branch feature_extractor. */
    Features features;
    if (extract_features_from_file(file_path, &features) != 0) {
        fprintf(stderr, "Error: failed to extract features from '%s'.\n", file_path);
        return 2;
    }

    /* Run rule engine using main branch score_features signature. */
    DetectionResult rule_result;
    if (score_features(&features, &rule_result, threshold) < 0) {
        fprintf(stderr, "Error: failed to score features.\n");
        return 3;
    }

    /* Run Python ML model via subprocess bridge. */
    PythonMLResult ml_result = run_python_model(&features);

    /* Combine rule score (60%) and ML probability (40%) into a hybrid score. */
    int ml_score = (int)(ml_result.probability * 100.0 + 0.5);
    int hybrid_score = (int)(0.6 * rule_result.score + 0.4 * ml_score + 0.5);
    if (hybrid_score > 100) hybrid_score = 100;
    if (hybrid_score < 0)   hybrid_score = 0;

    const char *rule_label   = rule_result.is_malware      ? "MALWARE" : "BENIGN";
    const char *ml_label     = (ml_result.label == 1)      ? "MALWARE" : "BENIGN";
    const char *hybrid_label = (hybrid_score >= threshold)  ? "MALWARE" : "BENIGN";

    printf("========================================\n");
    printf("ML-Enhanced Malware Scanner\n");
    printf("========================================\n");
    printf("File      : %s\n", file_path);
    printf("Threshold : %d\n", threshold);

    printf("\n--- Extracted Features ---\n");
    printf("  file_size      : %ld bytes\n", features.file_size);
    printf("  entropy        : %.4f\n",       features.entropy);
    printf("  keyword_count  : %d\n",         features.keyword_count);
    printf("  api_hit_count  : %d\n",         features.api_hit_count);
    printf("  has_mz_header  : %s\n",         features.has_mz_header ? "YES" : "NO");
    printf("  has_url        : %s\n",         features.has_url        ? "YES" : "NO");
    printf("  has_network    : %s\n",         features.has_network    ? "YES" : "NO");

    printf("\n--- Rule-Based Result ---\n");
    printf("  Score          : %d / 100\n", rule_result.score);
    printf("  Verdict        : %s\n",       rule_label);
    printf("  Rules fired    :\n");
    for (int i = 0; i < rule_result.rule_count; i++) {
        printf("    [+%d] %s\n", rule_result.fired_rule_points[i], rule_result.fired_rules[i]);
    }

    printf("\n--- Python ML Result ---\n");
    printf("  Probability    : %.4f\n", ml_result.probability);
    printf("  Verdict        : %s\n",   ml_label);

    printf("\n--- Hybrid Result ---\n");
    printf("  Hybrid score   : %d / 100\n", hybrid_score);
    printf("  Final verdict  : %s\n",       hybrid_label);

    return (hybrid_score >= threshold) ? 1 : 0;
}
