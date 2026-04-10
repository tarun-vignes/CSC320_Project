#ifndef PYTHON_ML_BRIDGE_H
#define PYTHON_ML_BRIDGE_H

#include "scanner_types.h"

/* Result returned from the Python ML model. */
typedef struct {
    /* Probability of maliciousness from 0.0 to 1.0. */
    double probability;
    /* Binary label: 1 = malicious, 0 = benign. */
    int label;
} PythonMLResult;

/* Runs the Python ML model via subprocess and returns its prediction. */
PythonMLResult run_python_model(const Features *features);

#endif
