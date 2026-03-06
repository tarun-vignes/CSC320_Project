#include "report.h"

#include <stdio.h>

/* Emits scan summary plus feature/rule transparency for writeups. */
void print_report(const char *path, const Features *features, const DetectionResult *result, int threshold) {
    const char *label = (result->score >= threshold) ? "suspicious" : "benign";

    printf("Scan target: %s\n", path);
    printf("Classification: %s\n", label);
    printf("Score: %d (threshold=%d)\n", result->score, threshold);

    printf("\nFeatures:\n");
    printf("  File size: %zu bytes\n", features->file_size);
    printf("  Byte entropy: %.4f\n", features->byte_entropy);
    printf("  Suspicious strings: %d\n", features->suspicious_string_hits);
    printf("  Suspicious imports: %d\n", features->suspicious_import_hits);
    printf("  MZ header: %s\n", features->has_mz_header ? "yes" : "no");

    printf("\nTriggered rules:\n");
    printf("  High entropy: %s\n", result->triggered_entropy ? "yes" : "no");
    printf("  String pattern threshold: %s\n", result->triggered_strings ? "yes" : "no");
    printf("  Import pattern threshold: %s\n", result->triggered_imports ? "yes" : "no");
    printf("  PE-like header bonus: %s\n", result->triggered_header ? "yes" : "no");
}
