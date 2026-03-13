#include "report.h"

#include <stdio.h>

/* Prints the per-file scan result used in demos and manual inspection. */
void print_report(const Features *features, const DetectionResult *result) {
    const char *verdict = result->is_malware ? "MALWARE" : "BENIGN";

    printf("=== MALWARE SCANNER REPORT ===\n");
    printf("Target  : %s\n", features->filepath);
    printf("Score   : %d / 100\n", result->score);
    printf("Verdict : %s\n", verdict);

    printf("\n--- Features ---\n");
    printf("  file_size      : %ld bytes\n", features->file_size);
    printf("  entropy        : %.2f\n", features->entropy);
    printf("  keyword_count  : %d\n", features->keyword_count);
    printf("  api_hit_count  : %d\n", features->api_hit_count);
    printf("  has_mz_header  : %s\n", features->has_mz_header ? "YES" : "NO");
    printf("  has_url        : %s\n", features->has_url ? "YES" : "NO");
    printf("  has_network    : %s\n", features->has_network ? "YES" : "NO");

    printf("\n--- Rules Fired ---\n");
    if (result->rule_count == 0) {
        printf("  none\n");
    }

    for (int i = 0; i < result->rule_count; ++i) {
        printf("  [+%d] %s\n", result->fired_rule_points[i], result->fired_rules[i]);
    }
}

/* Writes aggregate metrics from the dataset runner to a plain-text file. */
int write_summary_report(const char *path, int tp, int fp, int tn, int fn) {
    FILE *file = NULL;
    double total = (double)(tp + fp + tn + fn);
    double accuracy = 0.0;
    double precision = 0.0;
    double recall = 0.0;

    if (path == NULL) {
        return -1;
    }

    if (total > 0.0) {
        accuracy = ((double)(tp + tn) / total) * 100.0;
    }
    if ((tp + fp) > 0) {
        precision = ((double)tp / (double)(tp + fp)) * 100.0;
    }
    if ((tp + fn) > 0) {
        recall = ((double)tp / (double)(tp + fn)) * 100.0;
    }

    file = fopen(path, "w");
    if (file == NULL) {
        return -2;
    }

    fprintf(file, "Malware Scanner Evaluation Summary\n");
    fprintf(file, "=================================\n");
    fprintf(file, "True Positives : %d\n", tp);
    fprintf(file, "False Positives: %d\n", fp);
    fprintf(file, "True Negatives : %d\n", tn);
    fprintf(file, "False Negatives: %d\n", fn);
    fprintf(file, "Accuracy       : %.1f%%\n", accuracy);
    fprintf(file, "Precision      : %.1f%%\n", precision);
    fprintf(file, "Recall         : %.1f%%\n", recall);

    fclose(file);
    return 0;
}
