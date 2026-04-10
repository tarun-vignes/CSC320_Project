#ifndef PYTHON_ML_BRIDGE_H
#define PYTHON_ML_BRIDGE_H

/* 
   Header for the Python ML bridge.
   This lets C call the Python model and get back a result.
*/

#include "scanner_types.h"

/* 
   Stores the result returned by the Python ML script.
   probability = chance file is suspicious
   label = 1 means suspicious, 0 means benign
*/
typedef struct {
    double probability;
    int label;
} PythonMLResult;

/* 
   Runs the Python ML model using extracted features.
*/
PythonMLResult run_python_model(const Features *features);

#endif