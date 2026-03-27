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
#include <sys/stat.h>
#endif

/* Prints the supported CLI shape for single-file or folder scanning. */
static void print_usage(const char *exe_name) {
    printf("Usage: %s <file-or-folder> [--threshold N] [--csv output.csv]\n", exe_name);
    printf("Example: %s samples/ --threshold 50 --csv results/features.csv\n", exe_name);
}

/* Scans a single file and prints its report. Returns 1 if malware, 0 if benign. */
static int scan_file(const char *path, int threshold, const char *csv_path) {
    Features features;
    DetectionResult result;
    int rc = 0;

    rc = extract_features_from_file(path, &features);
    if (rc != 0) {
        fprintf(stderr, "Error: failed to analyze '%s' (code %d).\n", path, rc);
        return 0;
    }

    rc = score_features(&features, &result, threshold);
    if (rc < 0) {
        fprintf(stderr, "Error: failed to score '%s'.\n", path);
        return 0;
    }

    print_report(&features, &result);

    if (csv_path != NULL) {
        rc = append_features_csv(csv_path, &features, &result);
        if (rc != 0) {
            fprintf(stderr, "Warning: failed to append to CSV '%s' (code %d).\n", csv_path, rc);
        }
    }

    return result.is_malware ? 1 : 0;
}

#ifdef _WIN32

/* Returns 1 if the path is a directory, 0 otherwise. */
static int is_directory(const char *path) {
    DWORD attrs = GetFileAttributesA(path);
    return (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

/* Walks every file in a directory and scans each one. */
static int scan_directory(const char *directory, int threshold, const char *csv_path) {
    WIN32_FIND_DATAA find_data;
    HANDLE handle;
    char pattern[MAX_FILEPATH_LENGTH];
    char full_path[MAX_FILEPATH_LENGTH];
    int any_malware = 0;

    snprintf(pattern, sizeof(pattern), "%s\\*", directory);
    handle = FindFirstFileA(pattern, &find_data);
    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: could not open directory '%s'.\n", directory);
        return 0;
    }

    do {
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s\\%s", directory, find_data.cFileName);
        if (scan_file(full_path, threshold, csv_path)) {
            any_malware = 1;
        }
    } while (FindNextFileA(handle, &find_data));

    FindClose(handle);
    return any_malware;
}

#else

/* Returns 1 if the path is a directory, 0 otherwise. */
static int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return S_ISDIR(st.st_mode);
}

/* Walks every file in a directory and scans each one. */
static int scan_directory(const char *directory, int threshold, const char *csv_path) {
    DIR *dir = opendir(directory);
    struct dirent *entry;
    char full_path[MAX_FILEPATH_LENGTH];
    int any_malware = 0;

    if (dir == NULL) {
        fprintf(stderr, "Error: could not open directory '%s'.\n", directory);
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", directory, entry->d_name);
        if (scan_file(full_path, threshold, csv_path)) {
            any_malware = 1;
        }
    }

    closedir(dir);
    return any_malware;
}

#endif

int main(int argc, char **argv) {
    const char *input_path = NULL;
    const char *csv_path = NULL;
    int threshold = DEFAULT_THRESHOLD;
    int rc = 0;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    input_path = argv[1];

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

    /* Route to directory scan or single-file scan based on the input path. */
    if (is_directory(input_path)) {
        printf("Scanning directory: %s\n\n", input_path);
        rc = scan_directory(input_path, threshold, csv_path);
    } else {
        rc = scan_file(input_path, threshold, csv_path);
    }

    return rc;
}