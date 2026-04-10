#include "dataset_exporter.h"
#include "feature_extractor.h"
#include "scanner_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>

/*
 * Writes one labeled row to the CSV.
 * Columns match main branch scanner_types.h field names:
 *   file_name, file_size, entropy, keyword_count, api_hit_count,
 *   has_mz_header, has_url, has_network, label
 */
static int append_row(FILE *csv, const char *file_name, const Features *features, int label) {
    if (csv == NULL || features == NULL) {
        return -1;
    }

    fprintf(
        csv,
        "%s,%ld,%.6f,%d,%d,%d,%d,%d,%d\n",
        file_name,
        features->file_size,
        features->entropy,
        features->keyword_count,
        features->api_hit_count,
        features->has_mz_header,
        features->has_url,
        features->has_network,
        label
    );

    return 0;
}

/* Walks every regular file in dir_path, extracts features, and appends to csv. */
static int process_directory(const char *dir_path, int label, FILE *csv) {
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        fprintf(stderr, "Error: could not open directory '%s'.\n", dir_path);
        return -1;
    }

    struct dirent *entry;
    char full_path[MAX_FILEPATH_LENGTH];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }

        Features features;
        if (extract_features_from_file(full_path, &features) != 0) {
            fprintf(stderr, "Warning: skipping file (extraction error): %s\n", full_path);
            continue;
        }

        append_row(csv, entry->d_name, &features, label);
    }

    closedir(dir);
    return 0;
}

int build_dataset_from_directories(const char *benign_dir,
                                   const char *malicious_dir,
                                   const char *csv_path) {
    if (benign_dir == NULL || malicious_dir == NULL || csv_path == NULL) {
        return -1;
    }

    FILE *csv = fopen(csv_path, "w");
    if (csv == NULL) {
        fprintf(stderr, "Error: could not create CSV file '%s'.\n", csv_path);
        return -2;
    }

    /* Header matches field names in scanner_types.h */
    fprintf(csv,
        "file_name,file_size,entropy,keyword_count,api_hit_count,"
        "has_mz_header,has_url,has_network,label\n");

    process_directory(benign_dir, 0, csv);
    process_directory(malicious_dir, 1, csv);

    fclose(csv);
    printf("Dataset written to: %s\n", csv_path);
    return 0;
}
