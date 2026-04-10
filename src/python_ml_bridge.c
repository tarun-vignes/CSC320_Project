#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "python_ml_bridge.h"

/*
   Runs the Python ML script and reads back the result.
*/
PythonMLResult run_python_model(const Features *features) {
    PythonMLResult result;
    result.probability = 0.0;
    result.label = 0;

    /* Safety check */
    if (features == NULL) {
        return result;
    }

    char command[1024];

    /*
       Builds the command to run Python.
       Change python3 to python if needed on your machine.
    */
    snprintf(
        command,
        sizeof(command),
        "python3 ml/ml_runner.py %zu %.6f %d %d %d",
        features->file_size,
        features->byte_entropy,
        features->suspicious_string_hits,
        features->suspicious_import_hits,
        features->has_mz_header
    );

    /* Open a pipe to run Python and read its output */
    FILE *pipe = popen(command, "r");
    if (pipe == NULL) {
        fprintf(stderr, "Error: could not run Python script.\n");
        return result;
    }

    char buffer[512];

    /*
       Expected Python output:
       {"probability": 0.9321, "label": 1}
    */
    if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        double probability = 0.0;
        int label = 0;

        if (sscanf(buffer, "{\"probability\": %lf, \"label\": %d}", &probability, &label) == 2) {
            result.probability = probability;
            result.label = label;
        } else {
            fprintf(stderr, "Error: failed to parse Python output.\n");
        }
    } else {
        fprintf(stderr, "Error: Python script returned no output.\n");
    }

    pclose(pipe);
    return result;
}