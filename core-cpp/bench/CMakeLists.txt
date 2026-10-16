# C++ benchmarks of libekicore through its C ABI (built when EKI_BUILD_BENCH is ON).
# core-rs/benches/primitives.rs runs the same workloads, under the same names, against
# libekicore_rs; scripts/bench.sh builds and runs both and merges the results.

include(FetchContent)

FetchContent_Declare(googlebenchmark
  GIT_REPOSITORY https://github.com/google/benchmark.git
  GIT_TAG        v1.10.0
  GIT_SHALLOW    TRUE
  SYSTEM)

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(BENCHMARK_INSTALL_DOCS OFF CACHE BOOL "" FORCE)
set(BENCHMARK_INSTALL_TOOLS OFF CACHE BOOL "" FORCE)
# Newer compilers than the release was tested with must not fail the third-party build.
set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "" FORCE)

# Third-party code is not run through clang-tidy.
set(_eki_clang_tidy "${CMAKE_CXX_CLANG_TIDY}")
set(CMAKE_CXX_CLANG_TIDY "")
FetchContent_MakeAvailable(googlebenchmark)
set(CMAKE_CXX_CLANG_TIDY "${_eki_clang_tidy}")

add_executable(ekicore_bench primitives_bench.cpp)
# Only the public header and the exported eki_* functions: the benchmark is an ABI caller.
target_link_libraries(ekicore_bench PRIVATE ekicore ekicore_warnings benchmark::benchmark)
# This directory is added from the top level, not from core-cpp/, so it does not inherit
# core-cpp's CMAKE_CXX_STANDARD; set the same language level on the target.
set_target_properties(ekicore_bench PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF)
