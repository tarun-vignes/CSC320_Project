#include "rule_engine.h"

#include <stdio.h>

int main(void) {
    /* Construct a feature vector that should trigger multiple rules. */
    Features f;
    f.file_size = 1024;
    f.byte_entropy = 7.5;
    f.suspicious_string_hits = 2;
    f.suspicious_import_hits = 0;
    f.has_mz_header = 1;

    DetectionResult r = run_rules(&f, 70);
    if (r.score <= 0) {
        fprintf(stderr, "Expected positive score.\n");
        return 1;
    }

    printf("smoke test passed: score=%d\n", r.score);
    return 0;
}
