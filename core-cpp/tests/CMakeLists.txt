include(FetchContent)

FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.18.0
  GIT_SHALLOW    TRUE
  SYSTEM)

# Use the shared C runtime on Windows, matching the rest of the build; no effect elsewhere.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

# Third-party code is not run through clang-tidy.
set(_eki_clang_tidy "${CMAKE_CXX_CLANG_TIDY}")
set(CMAKE_CXX_CLANG_TIDY "")
FetchContent_MakeAvailable(googletest)
set(CMAKE_CXX_CLANG_TIDY "${_eki_clang_tidy}")

include(GoogleTest)

# Every *_test.cpp in this directory is part of the test binary, so a new test file needs no CMake edit.
file(GLOB EKI_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*_test.cpp")

add_executable(ekicore_tests ${EKI_TEST_SOURCES})
target_link_libraries(ekicore_tests PRIVATE ekicore ekicore_warnings GTest::gtest_main)

gtest_discover_tests(ekicore_tests)
