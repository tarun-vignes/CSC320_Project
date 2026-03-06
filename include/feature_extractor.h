#ifndef FEATURE_EXTRACTOR_H
#define FEATURE_EXTRACTOR_H

#include "scanner_types.h"

/* Returns 0 on success, negative value on extraction/read failure. */
int extract_features_from_file(const char *path, Features *out_features);

#endif
