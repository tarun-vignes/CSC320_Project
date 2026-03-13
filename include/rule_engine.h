#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include "scanner_types.h"

/* Scores extracted features, records fired rules, and sets the verdict flag. */
int score_features(const Features *features, DetectionResult *result, int threshold);

#endif
