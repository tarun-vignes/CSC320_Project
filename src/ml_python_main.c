#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "feature_extractor.h"
#include "rule_engine.h"
#include "python_ml_bridge.h"

/*
   Prints how to use the program.
*/
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
    int threshold = 70;

    /* Read optional threshold argument */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--threshold") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --threshold requires a value.\n");
                return 1;
            }
            threshold = atoi(argv[++i]);
        } else {
            fprintf(stderr, "Error: unknown argument '%s'\n", argv[i]);
            return 1;
        }
    }

    /* Extract file features using the existing scanner code */
    Features features;
    int extract_result = extract_features_from_file(file_path, &features);
    if (extract_result != 0) {
        fprintf(stderr, "Error: failed to extract features from '%s'\n", file_path);
        return 2;
    }

    /* Run existing rule-based logic */
    DetectionResult rules = run_rules(&features, threshold);

    /* Run Python ML model */
    PythonMLResult ml = run_python_model(&features);

    /* Combine rule score and ML score into a hybrid score */
    int ml_score = (int)(ml.probability * 100.0 + 0.5);
    int hybrid_score = (int)(0.6 * rules.score + 0.4 * ml_score + 0.5);

    const char *rule_label = (rules.score >= threshold) ? "suspicious" : "benign";
    const char *ml_label = (ml.label == 1) ? "suspicious" : "benign";
    const char *hybrid_label = (hybrid_score >= threshold) ? "suspicious" : "benign";

    /* Print results */
    printf("========================================\n");
    printf("ML-Enhanced Malware Scanner\n");
    printf("========================================\n");
    printf("File: %s\n", file_path);
    printf("Threshold: %d\n", threshold);

    printf("\nExtracted Features\n");
    printf("----------------------------------------\n");
    printf("File size: %zu bytes\n", features.file_size);
    printf("Byte entropy: %.4f\n", features.byte_entropy);
    printf("Suspicious strings: %d\n", features.suspicious_string_hits);
    printf("Suspicious imports: %d\n", features.suspicious_import_hits);
    printf("Has MZ header: %s\n", features.has_mz_header ? "yes" : "no");

    printf("\nRule-Based Result\n");
    printf("----------------------------------------\n");
    printf("Rule score: %d\n", rules.score);
    printf("Rule classification: %s\n", rule_label);

    printf("\nPython ML Result\n");
    printf("----------------------------------------\n");
    printf("ML probability: %.4f\n", ml.probability);
    printf("ML classification: %s\n", ml_label);

    printf("\nHybrid Result\n");
    printf("----------------------------------------\n");
    printf("Hybrid score: %d\n", hybrid_score);
    printf("Final classification: %s\n", hybrid_label);

    return 0;
}