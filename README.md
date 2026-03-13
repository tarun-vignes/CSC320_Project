# Rice's Theorem and Practical Malware Detection

## Project Purpose

This project implements a static malware scanner in C for a CSC320 research project on how Rice's Theorem constrains practical malware detection. The scanner does not execute programs. It reads files, extracts heuristic indicators, computes a score from `0` to `100`, and classifies each file as `BENIGN` or `MALWARE`.

The academic point is deliberate: perfect malware detection for all possible programs is undecidable, so the implementation focuses on explainable heuristics and measurable tradeoffs rather than claiming perfect certainty.

## Current Product

The repository now contains a working baseline product with:

- single-file scanning from the command line,
- static feature extraction,
- a weighted rule engine,
- human-readable reporting,
- CSV export for experiments,
- dataset evaluation with accuracy metrics,
- sample benign and suspicious dataset files.

## Scanner Workflow

The scanner processes a file in four steps:

1. `main.c` reads the target path and optional CLI arguments.
2. `feature_extractor.c` extracts static features from the file bytes.
3. `rule_engine.c` converts those features into a score and fired rules.
4. `report.c` prints the verdict and feature summary.

## Features Used

The current scanner extracts these features:

- `file_size`: total file size in bytes
- `entropy`: Shannon entropy of the file bytes
- `keyword_count`: suspicious string indicators such as `powershell`, `cmd.exe`, `inject`, or `socket(`
- `api_hit_count`: suspicious API names such as `VirtualAlloc`, `WriteProcessMemory`, and `CreateRemoteThread`
- `has_mz_header`: whether the file begins with `MZ`
- `has_url`: whether the file contains an embedded URL or IP-like pattern
- `has_network`: whether the file contains network-related code strings such as `connect(` or `recv(`

## Scoring and Threshold

The rule engine assigns points to suspicious indicators and clamps the final score to `0-100`.

Current default threshold: `50`

- `score < 50`: classify as `BENIGN`
- `score >= 50`: classify as `MALWARE`

This threshold is intentionally configurable because threshold tuning is part of the research story. Changing the threshold changes the false-positive and false-negative tradeoff, which helps demonstrate why heuristic detection is useful but imperfect.

## Command-Line Usage

### Build With GCC

```bash
gcc -std=c17 -Wall -Wextra -Wpedantic -Iinclude src/main.c src/feature_extractor.c src/rule_engine.c src/report.c src/utils.c -o scanner.exe -lm
gcc -std=c17 -Wall -Wextra -Wpedantic -Iinclude dataset/test_runner.c src/feature_extractor.c src/rule_engine.c src/report.c src/utils.c -o test_runner.exe -lm
gcc -std=c17 -Wall -Wextra -Wpedantic -Iinclude tests/smoke_test.c src/rule_engine.c src/utils.c -o smoke_test.exe
```

### Build With CMake

```bash
cmake -S . -B build
cmake --build build
```

### Scan One File

```bash
scanner.exe README.md --threshold 50 --csv results/features.csv
```

### Run Dataset Evaluation

```bash
test_runner.exe 50
```

The dataset runner scans `dataset/benign/` and `dataset/malware/`, appends per-file data to `results/features.csv`, and writes a summary to `results/report.txt`.

## Repository Layout

- `src/main.c`: command-line entrypoint
- `src/feature_extractor.c`: static feature extraction and CSV export
- `src/rule_engine.c`: heuristic scoring and malware decision
- `src/report.c`: scan report output and evaluation summary writer
- `src/utils.c`: helper functions for result/rule bookkeeping
- `include/`: shared structs and function declarations
- `tests/smoke_test.c`: sanity check for the rule engine
- `dataset/test_runner.c`: dataset evaluation harness
- `dataset/benign/`: safe sample inputs
- `dataset/malware/`: suspicious sample inputs
- `results/`: generated CSV and evaluation reports
- `docs/experiment-notes.md`: experiment notes

## Current Outputs

The single-file scanner prints:

- target file path,
- score out of `100`,
- final verdict,
- extracted feature values,
- which rules fired and how many points each contributed.

The dataset runner writes:

- `results/features.csv`
- `results/report.txt`

## March 31 Completion Plan

To make this a stronger final product by March 31, the next work items should be:

1. Add real PE import parsing instead of string-only API detection.
2. Improve folder scanning so the main scanner can accept a directory directly.
3. Expand the dataset with at least 20 benign and 20 suspicious offline samples.
4. Tune thresholds and rule weights using the dataset results.
5. Add a short evaluation section to the report showing false positives and false negatives.

## Safety Scope

This project is restricted to static analysis of files. It should not be used to execute or detonate live malware. Any evaluation should rely on approved offline samples and labeled datasets.
