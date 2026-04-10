#ifndef DATASET_EXPORTER_H
#define DATASET_EXPORTER_H

/*
 * Scans all files in benign_dir (label 0) and malicious_dir (label 1),
 * extracts features from each, and writes a labeled CSV to csv_path.
 * Returns 0 on success, negative on failure.
 */
int build_dataset_from_directories(const char *benign_dir,
                                   const char *malicious_dir,
                                   const char *csv_path);

#endif
