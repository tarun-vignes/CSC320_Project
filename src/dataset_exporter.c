#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>

#include "feature_extractor.h"
#include "dataset_exporter.h"

/*
  Writes one row to the CSV file
  Each row = one file + extracted features + label
*/
static int append_row(FILE *csv,
                      const char *file_name,
                      const Features *features,
                      int label) {

    if (csv == NULL || features == NULL) {
        return -1;
    }

    fprintf(csv, "%s,%zu,%.6f,%d,%d,%d,%d\n",
            file_name,
            features->file_size,
            features->byte_entropy,
            features->suspicious_string_hits,
            features->suspicious_import_hits,
            features->has_mz_header,
            label);

    return 0;
}

/*
  Goes through every file in a directory
  Extracts features and adds to CSV
*/
static int process_directory(const char *dir_path, int label, FILE *csv) {

    DIR *dir = opendir(dir_path);
    if (!dir) {
        fprintf(stderr, "Error opening directory: %s\n", dir_path);
        return -1;
    }

    struct dirent *entry;
    char full_path[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {

        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Build full path
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) != 0) {
            continue;
        }

        // Only process regular files (skip folders)
        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        // Extract features from file
        Features features;
        if (extract_features_from_file(full_path, &features) != 0) {
            printf("Skipping file (error): %s\n", full_path);
            continue;
        }

        // Add row to CSV
        append_row(csv, entry->d_name, &features, label);
    }

    closedir(dir);
    return 0;
}

/*
  Main function:
  Creates dataset/features.csv using both folders
*/
int build_dataset_from_directories(const char *benign_dir,
                                   const char *malicious_dir,
                                   const char *csv_path) {

    FILE *csv = fopen(csv_path, "w");
    if (!csv) {
        fprintf(stderr, "Error creating CSV file\n");
        return -1;
    }

    // CSV header
    fprintf(csv,
        "file_name,file_size,byte_entropy,suspicious_string_hits,"
        "suspicious_import_hits,has_mz_header,label\n");

    // Process benign files → label 0
    process_directory(benign_dir, 0, csv);

    // Process malicious files → label 1
    process_directory(malicious_dir, 1, csv);

    fclose(csv);

    printf("Dataset created: %s\n", csv_path);
    return 0;
}