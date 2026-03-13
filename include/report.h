#ifndef REPORT_H
#define REPORT_H

#include "scanner_types.h"

/* Prints a human-readable scan report for one target file. */
void print_report(const Features *features, const DetectionResult *result);
/* Writes aggregate dataset metrics to a plain-text summary file. */
int write_summary_report(const char *path, int tp, int fp, int tn, int fn);

#endif
