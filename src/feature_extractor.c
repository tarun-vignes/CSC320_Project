#include "feature_extractor.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Suspicious terms that often appear in malware-adjacent payloads or scripts. */
static const char *KEYWORD_INDICATORS[] = {
    "cmd.exe",
    "powershell",
    "system(",
    "exec(",
    "encrypt",
    "inject",
    "fork(",
    "socket(",
    "ransom",
    "payload"
};

/* API names associated with process injection or remote execution. */
static const char *API_INDICATORS[] = {
    "createremotethread",
    "virtualalloc",
    "writeprocessmemory",
    "winexec",
    "execve",
    "shellexecutea",
    "shellexecutew"
};

/* Network-related strings used as a lightweight communication indicator. */
static const char *NETWORK_INDICATORS[] = {
    "socket(",
    "connect(",
    "recv(",
    "send(",
    "wsastartup",
    "internetopen",
    "urldownloadtofile"
};

/* Computes Shannon entropy over the raw byte distribution. */
static double compute_entropy(const unsigned char *data, size_t len) {
    unsigned long counts[256] = {0};
    double entropy = 0.0;

    if (len == 0 || data == NULL) {
        return 0.0;
    }

    for (size_t i = 0; i < len; ++i) {
        counts[data[i]]++;
    }

    for (size_t i = 0; i < 256; ++i) {
        if (counts[i] == 0) {
            continue;
        }

        double probability = (double)counts[i] / (double)len;
        entropy -= probability * (log(probability) / log(2.0));
    }

    return entropy;
}

/* Converts arbitrary file bytes into a printable lowercase buffer for strstr(). */
static char *build_lowercase_view(const unsigned char *data, size_t len) {
    char *text = (char *)malloc(len + 1);
    if (text == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < len; ++i) {
        unsigned char ch = data[i];
        if (ch == '\0' || (!isprint(ch) && !isspace(ch))) {
            text[i] = ' ';
        } else {
            text[i] = (char)tolower(ch);
        }
    }
    text[len] = '\0';
    return text;
}

/* Counts how many configured indicators appear at least once. */
static int count_indicator_hits(const char *haystack, const char *const *needles, size_t needle_count) {
    int hits = 0;

    if (haystack == NULL) {
        return 0;
    }

    for (size_t i = 0; i < needle_count; ++i) {
        if (strstr(haystack, needles[i]) != NULL) {
            hits++;
        }
    }

    return hits;
}

/* Simple dotted-quad heuristic for spotting embedded IP-like strings. */
static int contains_ip_pattern(const char *text) {
    size_t dot_count = 0;

    if (text == NULL) {
        return 0;
    }

    for (size_t i = 0; text[i] != '\0'; ++i) {
        if (isdigit((unsigned char)text[i])) {
            size_t j = i;
            dot_count = 0;

            while (text[j] != '\0' && (isdigit((unsigned char)text[j]) || text[j] == '.')) {
                if (text[j] == '.') {
                    dot_count++;
                }
                j++;
            }

            if (dot_count >= 3) {
                return 1;
            }
        }
    }

    return 0;
}

/* URL detection combines protocol strings with a fallback IP pattern check. */
static int detect_url(const char *text) {
    if (text == NULL) {
        return 0;
    }

    return strstr(text, "http://") != NULL ||
           strstr(text, "https://") != NULL ||
           strstr(text, "ftp://") != NULL ||
           contains_ip_pattern(text);
}

int extract_features_from_file(const char *path, Features *out_features) {
    FILE *file = NULL;
    unsigned char *buffer = NULL;
    char *text_view = NULL;

    if (path == NULL || out_features == NULL) {
        return -1;
    }

    memset(out_features, 0, sizeof(*out_features));
    snprintf(out_features->filepath, sizeof(out_features->filepath), "%s", path);

    /* Read the entire file once so all heuristics operate on the same buffer. */
    file = fopen(path, "rb");
    if (file == NULL) {
        return -2;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -3;
    }

    out_features->file_size = ftell(file);
    if (out_features->file_size < 0) {
        fclose(file);
        return -4;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -5;
    }

    if (out_features->file_size > 0) {
        buffer = (unsigned char *)malloc((size_t)out_features->file_size);
        if (buffer == NULL) {
            fclose(file);
            return -6;
        }

        if (fread(buffer, 1, (size_t)out_features->file_size, file) != (size_t)out_features->file_size) {
            free(buffer);
            fclose(file);
            return -7;
        }
    }

    fclose(file);

    /* Binary-oriented features use the original bytes. */
    out_features->entropy = compute_entropy(buffer, (size_t)out_features->file_size);

    if (out_features->file_size >= 2 && buffer != NULL && buffer[0] == 'M' && buffer[1] == 'Z') {
        out_features->has_mz_header = 1;
    }

    /* String-based heuristics operate on a sanitized text view of the file. */
    text_view = build_lowercase_view(buffer, (size_t)out_features->file_size);
    if (text_view == NULL && out_features->file_size > 0) {
        free(buffer);
        return -8;
    }

    out_features->keyword_count = count_indicator_hits(
        text_view,
        KEYWORD_INDICATORS,
        sizeof(KEYWORD_INDICATORS) / sizeof(KEYWORD_INDICATORS[0])
    );

    out_features->api_hit_count = count_indicator_hits(
        text_view,
        API_INDICATORS,
        sizeof(API_INDICATORS) / sizeof(API_INDICATORS[0])
    );

    out_features->has_network = count_indicator_hits(
        text_view,
        NETWORK_INDICATORS,
        sizeof(NETWORK_INDICATORS) / sizeof(NETWORK_INDICATORS[0])
    ) > 0;

    out_features->has_url = detect_url(text_view);

    free(text_view);
    free(buffer);
    return 0;
}

int append_features_csv(const char *csv_path, const Features *features, const DetectionResult *result) {
    FILE *file = NULL;
    long existing_size = 0;

    if (csv_path == NULL || features == NULL || result == NULL) {
        return -1;
    }

    file = fopen(csv_path, "a+");
    if (file == NULL) {
        return -2;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -3;
    }

    /* Emit the header on the first write so analysis tools can ingest the file directly. */
    existing_size = ftell(file);
    if (existing_size == 0) {
        fprintf(file, "filepath,file_size,entropy,keyword_count,api_hit_count,has_mz_header,has_url,has_network,score,threshold,is_malware\n");
    }

    fprintf(
        file,
        "\"%s\",%ld,%.4f,%d,%d,%d,%d,%d,%d,%d,%d\n",
        features->filepath,
        features->file_size,
        features->entropy,
        features->keyword_count,
        features->api_hit_count,
        features->has_mz_header,
        features->has_url,
        features->has_network,
        result->score,
        result->threshold,
        result->is_malware
    );

    fclose(file);
    return 0;
}
