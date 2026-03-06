#include "feature_extractor.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* String indicators used by the baseline heuristic engine. */
static const char *SUSPICIOUS_STRINGS[] = {
    "CreateRemoteThread",
    "VirtualAlloc",
    "WriteProcessMemory",
    "WinExec",
    "cmd.exe",
    "powershell",
    "http://",
    "https://"
};

/* Shannon entropy over byte distribution. */
static double compute_entropy(const unsigned char *data, size_t len) {
    if (len == 0) {
        return 0.0;
    }

    unsigned long counts[256] = {0};
    for (size_t i = 0; i < len; ++i) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (counts[i] == 0) {
            continue;
        }
        double p = (double)counts[i] / (double)len;
        entropy -= p * (log(p) / log(2.0));
    }

    return entropy;
}

/* Counts how many configured indicators are present at least once. */
static int count_substring_hits(const unsigned char *data, size_t len) {
    int hits = 0;
    for (size_t s = 0; s < sizeof(SUSPICIOUS_STRINGS) / sizeof(SUSPICIOUS_STRINGS[0]); ++s) {
        const char *needle = SUSPICIOUS_STRINGS[s];
        size_t nlen = strlen(needle);
        if (nlen == 0 || nlen > len) {
            continue;
        }

        for (size_t i = 0; i <= len - nlen; ++i) {
            if (memcmp(data + i, needle, nlen) == 0) {
                hits++;
                break;
            }
        }
    }
    return hits;
}

int extract_features_from_file(const char *path, Features *out_features) {
    if (path == NULL || out_features == NULL) {
        return -1;
    }

    memset(out_features, 0, sizeof(*out_features));

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -2;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -3;
    }

    long file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        return -4;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -5;
    }

    unsigned char *buffer = NULL;
    if (file_size > 0) {
        buffer = (unsigned char *)malloc((size_t)file_size);
        if (buffer == NULL) {
            fclose(f);
            return -6;
        }

        size_t read_count = fread(buffer, 1, (size_t)file_size, f);
        if (read_count != (size_t)file_size) {
            free(buffer);
            fclose(f);
            return -7;
        }
    }

    fclose(f);

    out_features->file_size = (size_t)file_size;
    out_features->byte_entropy = compute_entropy(buffer, (size_t)file_size);
    out_features->suspicious_string_hits = count_substring_hits(buffer, (size_t)file_size);

    /* Basic PE-style header hint (Windows binaries). */
    if (file_size >= 2 && buffer[0] == 'M' && buffer[1] == 'Z') {
        out_features->has_mz_header = 1;
    }

    /* Placeholder for a real import parser (planned next step). */
    out_features->suspicious_import_hits = 0;

    free(buffer);
    return 0;
}
