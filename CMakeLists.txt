cmake_minimum_required(VERSION 3.16)
project(csc320_scanner C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include(CTest)

# Core scanner library used by executables
add_library(scanner_core
    src/feature_extractor.c
    src/rule_engine.c
    src/report.c
)

target_include_directories(scanner_core PUBLIC include)

# Link math library on non-Windows systems
if(NOT MSVC)
    target_link_libraries(scanner_core PRIVATE m)
endif()

# Original scanner executable
add_executable(scanner
    src/main.c
)

target_link_libraries(scanner PRIVATE scanner_core)

# New dataset builder executable
add_executable(build_dataset
    src/build_dataset_main.c
    src/dataset_exporter.c
)

target_link_libraries(build_dataset PRIVATE scanner_core)

# Compiler warnings
if(MSVC)
    target_compile_options(scanner_core PRIVATE /W4 /permissive-)
    target_compile_options(scanner PRIVATE /W4 /permissive-)
    target_compile_options(build_dataset PRIVATE /W4 /permissive-)
else()
    target_compile_options(scanner_core PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(scanner PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(build_dataset PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()