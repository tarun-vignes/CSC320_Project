#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include "scanner_types.h"

/* Produces a bounded risk score (0-100) and tracks which rules fired. */
DetectionResult run_rules(const Features *features, int threshold);

#endif
