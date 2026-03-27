#include "feature_extractor.h"

#include <ctype.h>
#include <math.h>
#include <stdint.h>
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

/* API names associated with injection, execution, or persistence. */
static const char *API_INDICATORS[] = {
    "createremotethread",
    "virtualalloc",
    "writeprocessmemory",
    "winexec",
    "execve",
    "shellexecutea",
    "shellexecutew",
    "createprocessa",
    "createprocessw"
};

/* Network-related strings used as a lightweight communication indicator. */
static const char *NETWORK_INDICATORS[] = {
    "socket(",
    "connect(",
    "recv(",
    "send(",
    "wsastartup",
    "internetopen",
    "internetopena",
    "internetopenw",
    "urldownloadtofile",
    "urldownloadtofilea",
    "urldownloadtofilew",
    "winhttpopen",
    "winhttpconnect"
};

/* Exact imported function names used when scanning PE import tables. */
static const char *NETWORK_IMPORT_INDICATORS[] = {
    "socket",
    "connect",
    "recv",
    "send",
    "wsastartup",
    "internetopen",
    "internetopena",
    "internetopenw",
    "urldownloadtofile",
    "urldownloadtofilea",
    "urldownloadtofilew",
    "winhttpopen",
    "winhttpconnect"
};

/* Imported DLLs that strongly imply network capability for PE binaries. */
static const char *NETWORK_DLL_INDICATORS[] = {
    "ws2_32.dll",
    "wininet.dll",
    "urlmon.dll",
    "winhttp.dll"
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

/* Safe little-endian readers for PE header parsing. */
static int read_u16_le(const unsigned char *data, size_t len, size_t offset, uint16_t *value) {
    if (data == NULL || value == NULL || offset + 2 > len) {
        return 0;
    }

    *value = (uint16_t)data[offset] |
             (uint16_t)((uint16_t)data[offset + 1] << 8);
    return 1;
}

static int read_u32_le(const unsigned char *data, size_t len, size_t offset, uint32_t *value) {
    if (data == NULL || value == NULL || offset + 4 > len) {
        return 0;
    }

    *value = (uint32_t)data[offset] |
             ((uint32_t)data[offset + 1] << 8) |
             ((uint32_t)data[offset + 2] << 16) |
             ((uint32_t)data[offset + 3] << 24);
    return 1;
}

static int read_u64_le(const unsigned char *data, size_t len, size_t offset, uint64_t *value) {
    if (data == NULL || value == NULL || offset + 8 > len) {
        return 0;
    }

    *value = (uint64_t)data[offset] |
             ((uint64_t)data[offset + 1] << 8) |
             ((uint64_t)data[offset + 2] << 16) |
             ((uint64_t)data[offset + 3] << 24) |
             ((uint64_t)data[offset + 4] << 32) |
             ((uint64_t)data[offset + 5] << 40) |
             ((uint64_t)data[offset + 6] << 48) |
             ((uint64_t)data[offset + 7] << 56);
    return 1;
}

/* Case-insensitive equality for imported function and DLL names. */
static int equals_ignore_case(const char *lhs, const char *rhs) {
    size_t i = 0;

    if (lhs == NULL || rhs == NULL) {
        return 0;
    }

    while (lhs[i] != '\0' && rhs[i] != '\0') {
        if (tolower((unsigned char)lhs[i]) != tolower((unsigned char)rhs[i])) {
            return 0;
        }
        i++;
    }

    return lhs[i] == '\0' && rhs[i] == '\0';
}

/* Checks whether a parsed import name matches any configured indicator exactly. */
static int matches_exact_indicator(const char *name, const char *const *needles, size_t needle_count) {
    for (size_t i = 0; i < needle_count; ++i) {
        if (equals_ignore_case(name, needles[i])) {
            return (int)i + 1;
        }
    }

    return 0;
}

/* Validates that a null-terminated string is fully present within the file buffer. */
static const char *get_string_at_offset(const unsigned char *data, size_t len, size_t offset) {
    if (data == NULL || offset >= len) {
        return NULL;
    }

    for (size_t i = offset; i < len; ++i) {
        if (data[i] == '\0') {
            return (const char *)(data + offset);
        }
    }

    return NULL;
}

/* Maps an RVA from the PE image into a file offset using the section table. */
static int rva_to_file_offset(
    const unsigned char *data,
    size_t len,
    size_t section_table_offset,
    uint16_t section_count,
    uint32_t rva,
    size_t *file_offset
) {
    if (data == NULL || file_offset == NULL || rva == 0) {
        return 0;
    }

    for (uint16_t i = 0; i < section_count; ++i) {
        size_t header_offset = section_table_offset + ((size_t)i * 40U);
        uint32_t virtual_size = 0;
        uint32_t virtual_address = 0;
        uint32_t raw_size = 0;
        uint32_t raw_pointer = 0;
        uint32_t mapped_size = 0;
        uint32_t delta = 0;

        if (header_offset + 40 > len) {
            return 0;
        }

        if (!read_u32_le(data, len, header_offset + 8, &virtual_size) ||
            !read_u32_le(data, len, header_offset + 12, &virtual_address) ||
            !read_u32_le(data, len, header_offset + 16, &raw_size) ||
            !read_u32_le(data, len, header_offset + 20, &raw_pointer)) {
            return 0;
        }

        mapped_size = virtual_size > raw_size ? virtual_size : raw_size;
        if (mapped_size == 0) {
            continue;
        }

        if (rva < virtual_address || rva >= virtual_address + mapped_size) {
            continue;
        }

        delta = rva - virtual_address;
        if (delta >= raw_size) {
            return 0;
        }

        *file_offset = (size_t)raw_pointer + delta;
        return *file_offset < len;
    }

    /* Headers often map directly, so allow a direct RVA->file offset fallback. */
    if ((size_t)rva < len) {
        *file_offset = (size_t)rva;
        return 1;
    }

    return 0;
}

/* Parses the PE import table and counts suspicious imported functions. */
static int parse_pe_imports(const unsigned char *data, size_t len, Features *features) {
    enum { IMAGE_DIRECTORY_ENTRY_IMPORT = 1 };
    uint32_t pe_offset = 0;
    uint16_t section_count = 0;
    uint16_t optional_magic = 0;
    uint16_t optional_size = 0;
    uint32_t number_of_directories = 0;
    uint32_t import_rva = 0;
    uint32_t import_size = 0;
    size_t optional_header_offset = 0;
    size_t section_table_offset = 0;
    size_t import_directory_offset = 0;
    size_t data_directory_relative = 0;
    size_t import_entry_offset = 0;
    int api_matches[sizeof(API_INDICATORS) / sizeof(API_INDICATORS[0])] = {0};
    int suspicious_import_hits = 0;
    int is_pe64 = 0;
    size_t max_descriptors = 0;

    if (data == NULL || features == NULL || len < 64) {
        return 0;
    }

    if (!features->has_mz_header) {
        return 0;
    }

    if (!read_u32_le(data, len, 0x3c, &pe_offset)) {
        return 0;
    }

    if ((size_t)pe_offset + 24 > len) {
        return 0;
    }

    if (memcmp(data + pe_offset, "PE\0\0", 4) != 0) {
        return 0;
    }

    if (!read_u16_le(data, len, (size_t)pe_offset + 6, &section_count) ||
        !read_u16_le(data, len, (size_t)pe_offset + 20, &optional_size)) {
        return 0;
    }

    optional_header_offset = (size_t)pe_offset + 24;
    if (optional_header_offset + optional_size > len) {
        return 0;
    }

    if (!read_u16_le(data, len, optional_header_offset, &optional_magic)) {
        return 0;
    }

    if (optional_magic == 0x10b) {
        data_directory_relative = 96;
    } else if (optional_magic == 0x20b) {
        data_directory_relative = 112;
        is_pe64 = 1;
    } else {
        return 0;
    }

    if (optional_size < data_directory_relative + 16) {
        return 0;
    }

    if (!read_u32_le(data, len, optional_header_offset + data_directory_relative - 4, &number_of_directories) ||
        number_of_directories <= IMAGE_DIRECTORY_ENTRY_IMPORT) {
        return 0;
    }

    import_entry_offset = optional_header_offset + data_directory_relative + (IMAGE_DIRECTORY_ENTRY_IMPORT * 8U);
    if (!read_u32_le(data, len, import_entry_offset, &import_rva) ||
        !read_u32_le(data, len, import_entry_offset + 4, &import_size) ||
        import_rva == 0 || import_size == 0) {
        return 0;
    }

    section_table_offset = optional_header_offset + optional_size;
    if (section_table_offset + ((size_t)section_count * 40U) > len) {
        return 0;
    }

    if (!rva_to_file_offset(data, len, section_table_offset, section_count, import_rva, &import_directory_offset)) {
        return 0;
    }

    max_descriptors = import_size / 20U;
    if (max_descriptors == 0 || max_descriptors > 256U) {
        max_descriptors = 256U;
    }

    for (size_t descriptor_index = 0; descriptor_index < max_descriptors; ++descriptor_index) {
        size_t descriptor_offset = import_directory_offset + (descriptor_index * 20U);
        uint32_t original_first_thunk = 0;
        uint32_t name_rva = 0;
        uint32_t first_thunk = 0;
        uint32_t thunk_rva = 0;
        size_t thunk_offset = 0;
        size_t name_offset = 0;

        if (descriptor_offset + 20 > len) {
            break;
        }

        if (!read_u32_le(data, len, descriptor_offset, &original_first_thunk) ||
            !read_u32_le(data, len, descriptor_offset + 12, &name_rva) ||
            !read_u32_le(data, len, descriptor_offset + 16, &first_thunk)) {
            break;
        }

        if (original_first_thunk == 0 && name_rva == 0 && first_thunk == 0) {
            break;
        }

        if (rva_to_file_offset(data, len, section_table_offset, section_count, name_rva, &name_offset)) {
            const char *dll_name = get_string_at_offset(data, len, name_offset);
            if (dll_name != NULL &&
                matches_exact_indicator(
                    dll_name,
                    NETWORK_DLL_INDICATORS,
                    sizeof(NETWORK_DLL_INDICATORS) / sizeof(NETWORK_DLL_INDICATORS[0])
                ) > 0) {
                features->has_network = 1;
            }
        }

        thunk_rva = original_first_thunk != 0 ? original_first_thunk : first_thunk;
        if (!rva_to_file_offset(data, len, section_table_offset, section_count, thunk_rva, &thunk_offset)) {
            continue;
        }

        for (size_t thunk_index = 0; thunk_index < 1024U; ++thunk_index) {
            size_t entry_offset = thunk_offset + (thunk_index * (is_pe64 ? 8U : 4U));
            uint32_t import_name_rva = 0;

            if (is_pe64) {
                uint64_t thunk_value = 0;
                size_t hint_name_offset = 0;
                const char *import_name = NULL;
                int indicator_index = 0;

                if (!read_u64_le(data, len, entry_offset, &thunk_value) || thunk_value == 0) {
                    break;
                }

                if ((thunk_value & 0x8000000000000000ULL) != 0) {
                    continue;
                }

                import_name_rva = (uint32_t)(thunk_value & 0x7fffffffffffffffULL);
                if (!rva_to_file_offset(data, len, section_table_offset, section_count, import_name_rva, &hint_name_offset)) {
                    continue;
                }

                import_name = get_string_at_offset(data, len, hint_name_offset + 2);
                if (import_name == NULL) {
                    continue;
                }

                indicator_index = matches_exact_indicator(
                    import_name,
                    API_INDICATORS,
                    sizeof(API_INDICATORS) / sizeof(API_INDICATORS[0])
                );
                if (indicator_index > 0 && !api_matches[indicator_index - 1]) {
                    api_matches[indicator_index - 1] = 1;
                    suspicious_import_hits++;
                }

                if (matches_exact_indicator(
                        import_name,
                        NETWORK_IMPORT_INDICATORS,
                        sizeof(NETWORK_IMPORT_INDICATORS) / sizeof(NETWORK_IMPORT_INDICATORS[0])
                    ) > 0) {
                    features->has_network = 1;
                }
            } else {
                uint32_t thunk_value = 0;
                size_t hint_name_offset = 0;
                const char *import_name = NULL;
                int indicator_index = 0;

                if (!read_u32_le(data, len, entry_offset, &thunk_value) || thunk_value == 0) {
                    break;
                }

                if ((thunk_value & 0x80000000UL) != 0) {
                    continue;
                }

                import_name_rva = thunk_value & 0x7fffffffUL;
                if (!rva_to_file_offset(data, len, section_table_offset, section_count, import_name_rva, &hint_name_offset)) {
                    continue;
                }

                import_name = get_string_at_offset(data, len, hint_name_offset + 2);
                if (import_name == NULL) {
                    continue;
                }

                indicator_index = matches_exact_indicator(
                    import_name,
                    API_INDICATORS,
                    sizeof(API_INDICATORS) / sizeof(API_INDICATORS[0])
                );
                if (indicator_index > 0 && !api_matches[indicator_index - 1]) {
                    api_matches[indicator_index - 1] = 1;
                    suspicious_import_hits++;
                }

                if (matches_exact_indicator(
                        import_name,
                        NETWORK_IMPORT_INDICATORS,
                        sizeof(NETWORK_IMPORT_INDICATORS) / sizeof(NETWORK_IMPORT_INDICATORS[0])
                    ) > 0) {
                    features->has_network = 1;
                }
            }
        }
    }

    return suspicious_import_hits;
}

int extract_features_from_file(const char *path, Features *out_features) {
    FILE *file = NULL;
    unsigned char *buffer = NULL;
    char *text_view = NULL;
    int string_api_hits = 0;
    int pe_import_hits = 0;

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

    string_api_hits = count_indicator_hits(
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

    /*
     * Prefer parsed PE imports when available, but keep the string-based API
     * scan as a fallback for non-PE files and plain-text samples.
     */
    pe_import_hits = parse_pe_imports(buffer, (size_t)out_features->file_size, out_features);
    out_features->api_hit_count = pe_import_hits > string_api_hits ? pe_import_hits : string_api_hits;

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
