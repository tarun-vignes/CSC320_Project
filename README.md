# Rice's Theorem and Practical Malware Detection

## Project Overview

This project implements a static, heuristic malware scanner in C. Its purpose is to support a course study of how Rice's Theorem constrains practical malware detection. The scanner does not attempt to perfectly decide whether an arbitrary program is malicious. Instead, it extracts observable file features and applies weighted rules to classify a target as `benign` or `suspicious`.

The project is designed to demonstrate a central theoretical point: any detector that tries to determine non-trivial semantic properties of arbitrary programs will face unavoidable limitations. In practice, malware detection systems therefore rely on approximations, heuristics, and probabilistic judgments rather than perfect decision procedures.

## Problem Statement

Rice's Theorem states that every non-trivial semantic property of programs is undecidable. Malware detection is a practical example of this limit. Determining whether a program is malicious depends on its behavior and intent, which are semantic properties rather than simple syntactic facts.

This project addresses that gap between theory and practice by building a detector that:

- analyzes executable-like files without executing them,
- uses imperfect but explainable heuristic features,
- produces transparent scores and rule triggers,
- supports measurement of false positives and false negatives.

## Project Goals

- Build a safe malware-analysis prototype in C.
- Perform static analysis only; no live malware execution.
- Show how real detectors rely on partial evidence instead of perfect certainty.
- Provide output suitable for experiments, screenshots, demonstrations, and discussion in a written report.

## Current Implementation

The current baseline scanner performs the following steps:

1. Reads a target file from disk.
2. Extracts simple static features:
   - file size,
   - Shannon byte entropy,
   - suspicious string indicators,
   - presence of an `MZ` header,
   - placeholder import-based indicators.
3. Applies a weighted rule engine to compute a score from `0` to `100`.
4. Labels the file as `benign` or `suspicious` based on a configurable threshold.
5. Prints a transparent report showing extracted features and triggered rules.

## Planned Extensions

The baseline is intended to grow into a more complete experiment platform. Planned next steps include:

- parsing PE imports from Windows executables,
- scanning entire directories of samples,
- exporting results for evaluation,
- comparing thresholds across labeled datasets,
- measuring false-positive and false-negative rates.

These extensions will make it easier to connect the implementation to the theoretical discussion in the paper and presentation.

## Project Structure

- `src/main.c`: command-line entrypoint and control flow
- `src/feature_extractor.c`: static feature extraction
- `src/rule_engine.c`: heuristic scoring logic
- `src/report.c`: human-readable output
- `include/`: shared types and function declarations
- `tests/smoke_test.c`: basic scoring sanity check
- `docs/experiment-notes.md`: project notes for evaluation design

## Build Instructions

### CMake

```bash
cmake -S . -B build
cmake --build build
```

### GCC

```bash
gcc -std=c17 -Wall -Wextra -Wpedantic -Iinclude src/main.c src/feature_extractor.c src/rule_engine.c src/report.c -o scanner.exe -lm
```

## Usage

```bash
scanner <path-to-file> --threshold 70
```

Example:

```bash
scanner sample.exe --threshold 70
```

## Safety Statement

This project is restricted to static file analysis. It should not be used to execute, detonate, or interact with live malware. Any experimental evaluation should use approved datasets and offline samples in a controlled academic environment.

## Theoretical Relevance

This scanner is intentionally heuristic. That is not a defect in the project design; it is part of the point. The existence of false positives and false negatives helps illustrate why malware detection cannot be made perfect for all possible programs. The system therefore serves as both a software artifact and a concrete demonstration of the theoretical limits described by Rice's Theorem.

## Status

The current version is a working baseline prototype. It compiles, runs, and produces interpretable output, but it is not yet a full research-grade detector. Its present role is to establish the project architecture and provide a foundation for further experiments.
