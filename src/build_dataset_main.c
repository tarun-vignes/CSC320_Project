#include "dataset_exporter.h"

#include <stdio.h>

/* CLI tool to generate the labeled feature CSV from two directories. */
int main(int argc, char **argv) {
    if (argc != 4) {
        printf("Usage: %s <benign_dir> <malicious_dir> <output_csv>\n", argv[0]);
        printf("Example: %s dataset/benign dataset/malware dataset/features.csv\n", argv[0]);
        return 1;
    }

    const char *benign   = argv[1];
    const char *malware  = argv[2];
    const char *output   = argv[3];

    if (build_dataset_from_directories(benign, malware, output) != 0) {
        fprintf(stderr, "Error: failed to build dataset.\n");
        return 1;
    }

    printf("Dataset ready for ML training.\n");
    return 0;
}
