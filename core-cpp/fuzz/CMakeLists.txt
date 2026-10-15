# libFuzzer targets for libekicore. Added by the root CMakeLists.txt when EKI_BUILD_FUZZ is ON;
# the `fuzz` preset turns it on together with EKI_SANITIZE and a clang that ships libFuzzer.
#
#   cmake --preset fuzz && cmake --build --preset fuzz
#   build/fuzz/core-cpp/fuzz/fuzz_aead_open -runs=2000 core-cpp/fuzz/corpus/fuzz_aead_open

# Apple clang has no libFuzzer runtime, and GCC has no libFuzzer at all.
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  message(FATAL_ERROR
    "EKI_BUILD_FUZZ needs LLVM clang with libFuzzer, but the C++ compiler is "
    "${CMAKE_CXX_COMPILER_ID} (${CMAKE_CXX_COMPILER}). On macOS use Homebrew LLVM: "
    "-DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ "
    "-DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang (the `fuzz` preset does this).")
endif()

if(NOT EKI_SANITIZE)
  message(WARNING
    "EKI_BUILD_FUZZ without EKI_SANITIZE: libekicore is built without ASan/UBSan, so memory "
    "errors inside the library go unnoticed. The `fuzz` preset sets both.")
endif()

set(_eki_fuzz_flags -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)

# Coverage feedback from inside the library: without it libFuzzer only sees the target's own
# branches. fuzzer-no-link adds the instrumentation but not libFuzzer's main().
foreach(_eki_target IN ITEMS ekicore ekicore_primitives)
  target_compile_options(${_eki_target} PRIVATE -fsanitize=fuzzer-no-link)
endforeach()

foreach(_eki_fuzzer IN ITEMS fuzz_aead_open fuzz_ks_unwrap fuzz_ffi_status)
  add_executable(${_eki_fuzzer} ${_eki_fuzzer}.cpp)
  target_compile_features(${_eki_fuzzer} PRIVATE cxx_std_20)
  target_compile_options(${_eki_fuzzer} PRIVATE ${_eki_fuzz_flags})
  target_link_options(${_eki_fuzzer} PRIVATE ${_eki_fuzz_flags})
  target_include_directories(${_eki_fuzzer} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(${_eki_fuzzer} PRIVATE ekicore ekicore_warnings)
endforeach()
