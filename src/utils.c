#include "utils.h"

#include <stdio.h>
#include <string.h>

/* Initializes all result fields before the rule engine starts logging hits. */
void reset_detection_result(DetectionResult *result, int threshold) {
    if (result == NULL) {
        return;
    }

    memset(result, 0, sizeof(*result));
    result->threshold = threshold;
}

/* Stores the rule label and point value for later reporting. */
void log_rule(DetectionResult *result, const char *rule_name, int points) {
    if (result == NULL || rule_name == NULL) {
        return;
    }

    if (result->rule_count >= MAX_RULES_FIRED) {
        return;
    }

    snprintf(
        result->fired_rules[result->rule_count],
        sizeof(result->fired_rules[result->rule_count]),
        "%s",
        rule_name
    );
    result->fired_rule_points[result->rule_count] = points;
    result->rule_count++;
}
