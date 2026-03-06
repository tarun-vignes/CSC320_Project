#include "feature_extractor.h"
#include "report.h"
#include "rule_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CLI help for the baseline scanner entrypoint. */
static void print_usage(const char *exe_name) {
    printf("Usage: %s <file-path> [--threshold N]\n", exe_name);
    printf("Example: %s sample.exe --threshold 70\n", exe_name);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *file_path = argv[1];
    int threshold = 70;

    /* Parse optional threshold override. */
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
        } else {
            fprintf(stderr, "Error: unknown argument '%s'.\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Extract static file features and map them to a heuristic score. */
    Features features;
    int rc = extract_features_from_file(file_path, &features);
    if (rc != 0) {
        fprintf(stderr, "Error: failed to analyze '%s' (code %d).\n", file_path, rc);
        return 2;
    }

    DetectionResult result = run_rules(&features, threshold);
    print_report(file_path, &features, &result, threshold);

    return 0;
}
