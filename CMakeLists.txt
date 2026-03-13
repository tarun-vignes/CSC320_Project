cmake_minimum_required(VERSION 3.16)
project(csc320_scanner C)

# Build everything as portable C17.
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
include(CTest)

# Shared core library used by the CLI scanner, dataset runner, and tests.
add_library(scanner_core
    src/feature_extractor.c
    src/rule_engine.c
    src/report.c
    src/utils.c
)

target_include_directories(scanner_core PUBLIC include)
if(NOT MSVC)
  # GCC/Clang need libm for entropy calculations.
  target_link_libraries(scanner_core PRIVATE m)
endif()

# Single-file scanner CLI.
add_executable(scanner src/main.c)
target_link_libraries(scanner PRIVATE scanner_core)

if(MSVC)
  target_compile_options(scanner_core PRIVATE /W4 /permissive-)
  target_compile_options(scanner PRIVATE /W4 /permissive-)
else()
  target_compile_options(scanner_core PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(scanner PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

# Dataset evaluator for accuracy, precision, and recall experiments.
add_executable(test_runner dataset/test_runner.c)
target_link_libraries(test_runner PRIVATE scanner_core)

if(MSVC)
  target_compile_options(test_runner PRIVATE /W4 /permissive-)
else()
  target_compile_options(test_runner PRIVATE -Wall -Wextra -Wpedantic)
endif()
