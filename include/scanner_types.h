#ifndef SCANNER_TYPES_H
#define SCANNER_TYPES_H

#include <stddef.h>

/* Raw static features extracted from a single file. */
typedef struct {
    size_t file_size;
    double byte_entropy;
    int suspicious_string_hits;
    int suspicious_import_hits;
    int has_mz_header;
} Features;

/* Rule-engine output used for reporting and threshold classification. */
typedef struct {
    int score;
    int triggered_entropy;
    int triggered_strings;
    int triggered_imports;
    int triggered_header;
} DetectionResult;

#endif
