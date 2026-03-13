#ifndef UTILS_H
#define UTILS_H

#include "scanner_types.h"

/* Clears a result struct before applying rules. */
void reset_detection_result(DetectionResult *result, int threshold);
/* Adds a named scoring rule to the result if capacity remains. */
void log_rule(DetectionResult *result, const char *rule_name, int points);

#endif
