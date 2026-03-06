#ifndef REPORT_H
#define REPORT_H

#include "scanner_types.h"

/* Prints a human-readable scan report for one target file. */
void print_report(const char *path, const Features *features, const DetectionResult *result, int threshold);

#endif
