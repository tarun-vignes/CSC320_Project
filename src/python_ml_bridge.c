#include "python_ml_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Runs the Python ML script and reads back the result. */
PythonMLResult run_python_model(const Features *features) {
    PythonMLResult result;
    result.probability = 0.0;
    result.label = 0;

    if (features == NULL) {
        return result;
    }

    char command[1024];

    /*
     * Passes features to the Python runner as CLI arguments.
     * Field names match main branch scanner_types.h:
     *   file_size, entropy, keyword_count, api_hit_count, has_mz_header
     * Change python3 to python if needed on your machine.
     */
    snprintf(
        command,
        sizeof(command),
        "python3 ml/ml_runner.py %ld %.6f %d %d %d %d %d",
        features->file_size,
        features->entropy,
        features->keyword_count,
        features->api_hit_count,
        features->has_mz_header,
        features->has_url,
        features->has_network
    );

    FILE *pipe = popen(command, "r");
    if (pipe == NULL) {
        fprintf(stderr, "Error: could not run Python ML script.\n");
        return result;
    }

    char buffer[512];

    /*
     * Expected Python output format:
     * {"probability": 0.9321, "label": 1}
     */
    if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        double probability = 0.0;
        int label = 0;

        if (sscanf(buffer, "{\"probability\": %lf, \"label\": %d}", &probability, &label) == 2) {
            result.probability = probability;
            result.label = label;
        } else {
            fprintf(stderr, "Error: failed to parse Python output: %s\n", buffer);
        }
    } else {
        fprintf(stderr, "Error: Python script returned no output.\n");
    }

    pclose(pipe);
    return result;
}
