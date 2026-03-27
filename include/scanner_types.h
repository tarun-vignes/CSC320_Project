#ifndef SCANNER_TYPES_H
#define SCANNER_TYPES_H

#include <stddef.h>

/* Shared scanner defaults and storage limits. */
#define DEFAULT_THRESHOLD 50
#define MAX_FILEPATH_LENGTH 512
#define MAX_RULES_FIRED 16

/* Raw static features extracted from a single file. */
typedef struct {
    /* Original path supplied to the scanner. */
    char filepath[MAX_FILEPATH_LENGTH];
    /* File size in bytes from ftell(). */
    long file_size;
    /* Shannon entropy across raw file bytes. */
    double entropy;
    /* Count of suspicious keywords found in the file text view. */
    int keyword_count;
    /* Count of suspicious API names found via PE imports or string fallback. */
    int api_hit_count;
    /* Whether the file begins with the PE-style MZ signature. */
    int has_mz_header;
    /* Whether a URL or IP-like pattern appears in the file. */
    int has_url;
    /* Whether network-related code strings appear in the file. */
    int has_network;
} Features;

/* Rule-engine output used for reporting and threshold classification. */
typedef struct {
    /* Final bounded risk score from 0 to 100. */
    int score;
    /* Threshold used during this classification run. */
    int threshold;
    /* Boolean verdict derived from score >= threshold. */
    int is_malware;
    /* Number of named rules that fired while scoring. */
    int rule_count;
    /* Rule labels recorded in scoring order. */
    char fired_rules[MAX_RULES_FIRED][32];
    /* Point contribution for each fired rule. */
    int fired_rule_points[MAX_RULES_FIRED];
} DetectionResult;

#endif
