# libFuzzer targets for libekicore. Added by the root CMakeLists.txt when EKI_BUILD_FUZZ is ON;
# the `fuzz` preset turns it on together with EKI_SANITIZE and a clang that ships libFuzzer.
#
#   cmake --preset fuzz && cmake --build --preset fuzz
#   mkdir -p /tmp/eki-corpus && build/fuzz/core-cpp/fuzz/fuzz_aead_open -runs=200000 \
#     /tmp/eki-corpus core-cpp/fuzz/corpus/fuzz_aead_open
#
# libFuzzer writes new inputs to the first corpus directory only, so the committed seeds stay as
# they are.
# The hybrid KEM target exercises the KEM only in a build with -DEKI_WITH_PQ=ON.

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

# The audit log oracle hashes records with SHA-256. OpenSSL::Crypto, imported in core-cpp/, is not
# visible from this directory, which the root CMakeLists.txt adds; core-cpp/ has already cached
# OPENSSL_ROOT_DIR, so this finds the same installation.
find_package(OpenSSL 3.0 REQUIRED)

set(_eki_fuzz_flags -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)

# Coverage feedback from inside the library: without it libFuzzer only sees the target's own
# branches. fuzzer-no-link adds the instrumentation but not libFuzzer's main().
foreach(_eki_target IN ITEMS ekicore ekicore_primitives)
  target_compile_options(${_eki_target} PRIVATE -fsanitize=fuzzer-no-link)
endforeach()

foreach(_eki_fuzzer IN ITEMS
    fuzz_aead_open
    fuzz_hkdf
    fuzz_ffi_status
    fuzz_ks_unwrap
    fuzz_audit_verify
    fuzz_hybrid_kem
    fuzz_ecdsa_sign_verify)
  add_executable(${_eki_fuzzer} ${_eki_fuzzer}.cpp)
  target_compile_features(${_eki_fuzzer} PRIVATE cxx_std_20)
  target_compile_options(${_eki_fuzzer} PRIVATE ${_eki_fuzz_flags})
  target_link_options(${_eki_fuzzer} PRIVATE ${_eki_fuzz_flags})
  target_include_directories(${_eki_fuzzer} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  # The targets check what the build options promise: which statuses mean "not compiled in".
  target_compile_definitions(${_eki_fuzzer} PRIVATE
    EKI_FUZZ_WITH_PKCS11=$<BOOL:${EKI_WITH_PKCS11}>
    EKI_FUZZ_WITH_PQ=$<BOOL:${EKI_WITH_PQ}>)
  target_link_libraries(${_eki_fuzzer} PRIVATE ekicore ekicore_warnings OpenSSL::Crypto)
endforeach()
