cmake_minimum_required(VERSION 3.25)

project(ekibridge VERSION 0.1.0 LANGUAGES C CXX)

option(EKI_BUILD_TESTS "Build the C++ unit tests (fetches GoogleTest)" ON)
option(EKI_BUILD_BENCH "Build the C++ benchmarks (fetches Google Benchmark)" OFF)
option(EKI_BUILD_FUZZ "Build the libFuzzer targets (needs a clang with libFuzzer)" OFF)
option(EKI_WITH_PKCS11 "Compile the PKCS#11 key store backend" ON)
option(EKI_WITH_PQ "Compile the hybrid X25519 + ML-KEM-768 KEM (needs OpenSSL >= 3.5)" OFF)
option(EKI_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(EKI_MLOCK "Lock secret buffers in memory, best effort" ON)

enable_testing()

add_subdirectory(core-cpp)

# Optional pieces owned by other packages: they join the build as soon as their CMakeLists.txt exists.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/interop/cpp-caller/CMakeLists.txt")
  add_subdirectory(interop/cpp-caller)
endif()

if(EKI_BUILD_BENCH AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/core-cpp/bench/CMakeLists.txt")
  add_subdirectory(core-cpp/bench)
endif()

if(EKI_BUILD_FUZZ AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/core-cpp/fuzz/CMakeLists.txt")
  add_subdirectory(core-cpp/fuzz)
endif()
