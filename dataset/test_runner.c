#include "feature_extractor.h"
#include "report.h"
#include "rule_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif

/* Aggregate confusion-matrix counts for dataset evaluation. */
typedef struct {
    int true_positives;
    int false_positives;
    int true_negatives;
    int false_negatives;
} Metrics;

/* Runs one file through extraction and scoring, then updates evaluation counters. */
static int process_file(const char *path, int expected_malware, int threshold, Metrics *metrics) {
    Features features;
    DetectionResult result;
    int rc = extract_features_from_file(path, &features);

    if (rc != 0) {
        fprintf(stderr, "Warning: failed to analyze '%s' (code %d).\n", path, rc);
        return rc;
    }

    score_features(&features, &result, threshold);
    append_features_csv("results/features.csv", &features, &result);

    /* Compare scanner output against the dataset label. */
    if (expected_malware) {
        if (result.is_malware) {
            metrics->true_positives++;
        } else {
            metrics->false_negatives++;
        }
    } else {
        if (result.is_malware) {
            metrics->false_positives++;
        } else {
            metrics->true_negatives++;
        }
    }

    return 0;
}

#ifdef _WIN32
/* Windows directory walk for the benign and malware dataset folders. */
static int scan_directory(const char *directory, int expected_malware, int threshold, Metrics *metrics) {
    WIN32_FIND_DATAA find_data;
    HANDLE handle;
    char pattern[MAX_FILEPATH_LENGTH];
    char full_path[MAX_FILEPATH_LENGTH];

    snprintf(pattern, sizeof(pattern), "%s\\*", directory);
    handle = FindFirstFileA(pattern, &find_data);
    if (handle == INVALID_HANDLE_VALUE) {
        return -1;
    }

    do {
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s\\%s", directory, find_data.cFileName);
        process_file(full_path, expected_malware, threshold, metrics);
    } while (FindNextFileA(handle, &find_data));

    FindClose(handle);
    return 0;
}
#else
/* POSIX directory walk fallback for non-Windows builds. */
static int scan_directory(const char *directory, int expected_malware, int threshold, Metrics *metrics) {
    DIR *dir = opendir(directory);
    struct dirent *entry;
    char full_path[MAX_FILEPATH_LENGTH];

    if (dir == NULL) {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", directory, entry->d_name);
        process_file(full_path, expected_malware, threshold, metrics);
    }

    closedir(dir);
    return 0;
}
#endif

int main(int argc, char **argv) {
    Metrics metrics = {0};
    int threshold = DEFAULT_THRESHOLD;

    if (argc > 1) {
        threshold = atoi(argv[1]);
        if (threshold < 0 || threshold > 100) {
            fprintf(stderr, "Threshold must be between 0 and 100.\n");
            return 1;
        }
    }

    /* Evaluate clean and suspicious datasets separately so FP/FN stay explicit. */
    if (scan_directory("dataset/benign", 0, threshold, &metrics) != 0) {
        fprintf(stderr, "Warning: could not scan dataset/benign\n");
    }
    if (scan_directory("dataset/malware", 1, threshold, &metrics) != 0) {
        fprintf(stderr, "Warning: could not scan dataset/malware\n");
    }

    printf(
        "Accuracy inputs: TP=%d FP=%d TN=%d FN=%d\n",
        metrics.true_positives,
        metrics.false_positives,
        metrics.true_negatives,
        metrics.false_negatives
    );

    if (write_summary_report(
        "results/report.txt",
        metrics.true_positives,
        metrics.false_positives,
        metrics.true_negatives,
        metrics.false_negatives
    ) != 0) {
        fprintf(stderr, "Warning: failed to write results/report.txt\n");
    }

    return 0;
}
