#include "feature_extractor.h"
#include "report.h"
#include "rule_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Prints the supported CLI shape for single-file scanning. */
static void print_usage(const char *exe_name) {
    printf("Usage: %s <file-path> [--threshold N] [--csv output.csv]\n", exe_name);
    printf("Example: %s sample.exe --threshold 50 --csv results/features.csv\n", exe_name);
}

int main(int argc, char **argv) {
    const char *file_path = NULL;
    const char *csv_path = NULL;
    int threshold = DEFAULT_THRESHOLD;
    Features features;
    DetectionResult result;
    int rc = 0;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    file_path = argv[1];

    /* Parse optional score threshold and CSV output destination. */
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--threshold") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --threshold requires a value.\n");
                return 1;
            }

            threshold = atoi(argv[i + 1]);
            if (threshold < 0 || threshold > 100) {
                fprintf(stderr, "Error: threshold must be between 0 and 100.\n");
                return 1;
            }
            i++;
        } else if (strcmp(argv[i], "--csv") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --csv requires a file path.\n");
                return 1;
            }
            csv_path = argv[i + 1];
            i++;
        } else {
            fprintf(stderr, "Error: unknown argument '%s'.\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Extract static features from the target file before scoring it. */
    rc = extract_features_from_file(file_path, &features);
    if (rc != 0) {
        fprintf(stderr, "Error: failed to analyze '%s' (code %d).\n", file_path, rc);
        return 2;
    }

    /* Apply the heuristic rule engine to produce a verdict. */
    rc = score_features(&features, &result, threshold);
    if (rc < 0) {
        fprintf(stderr, "Error: failed to score '%s'.\n", file_path);
        return 3;
    }

    print_report(&features, &result);

    /* Optional CSV output is useful for dataset experiments. */
    if (csv_path != NULL) {
        rc = append_features_csv(csv_path, &features, &result);
        if (rc != 0) {
            fprintf(stderr, "Warning: failed to append to CSV '%s' (code %d).\n", csv_path, rc);
        }
    }

    return result.is_malware ? 1 : 0;
}
