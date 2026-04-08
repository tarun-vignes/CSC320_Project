#include <stdio.h>
#include "dataset_exporter.h"

/*
  CLI tool to generate dataset CSV
*/
int main(int argc, char **argv) {

    if (argc != 4) {
        printf("Usage: %s <benign_dir> <malicious_dir> <output_csv>\n", argv[0]);
        return 1;
    }

    const char *benign = argv[1];
    const char *malicious = argv[2];
    const char *output = argv[3];

    // Build dataset
    if (build_dataset_from_directories(benign, malicious, output) != 0) {
        printf("Failed to build dataset\n");
        return 1;
    }

    printf("Dataset ready for training\n");
    return 0;
}