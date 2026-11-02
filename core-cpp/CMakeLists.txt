# libekicore: the C++ implementation of the ekicore C ABI, on top of OpenSSL 3.

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Homebrew's OpenSSL is keg-only, so CMake does not find it on its own. An explicit
# OPENSSL_ROOT_DIR (cache or environment) always wins; otherwise try the usual Homebrew prefixes.
# This is done here and not in CMakePresets.json because a preset cannot express "use this unless
# the environment says otherwise", and a preset condition would disable the preset off macOS.
if(APPLE AND NOT OPENSSL_ROOT_DIR AND "$ENV{OPENSSL_ROOT_DIR}" STREQUAL "")
  foreach(_eki_prefix IN ITEMS /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3)
    if(EXISTS "${_eki_prefix}/include/openssl/ssl.h")
      set(OPENSSL_ROOT_DIR "${_eki_prefix}" CACHE PATH "OpenSSL installation prefix" FORCE)
      break()
    endif()
  endforeach()
endif()

find_package(OpenSSL 3.0 REQUIRED)

if(EKI_WITH_PQ AND OPENSSL_VERSION VERSION_LESS 3.5)
  message(FATAL_ERROR "EKI_WITH_PQ needs OpenSSL >= 3.5 for ML-KEM (found ${OPENSSL_VERSION})")
endif()

if(EKI_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

# Warning set shared by the library and the tests. Third-party code (GoogleTest) does not get it.
add_library(ekicore_warnings INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(ekicore_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wsign-conversion)
endif()

# The cryptographic primitives (namespace ekicore, declared in ekicore/primitives.hpp) are an object
# library: they are compiled once and linked both into libekicore and into the unit tests. The tests
# cannot reach them through the shared library, which exports nothing but the eki_* functions.
add_library(ekicore_primitives OBJECT
  src/hmac.cpp
  src/hkdf.cpp
  src/aead.cpp
  src/ecdsa.cpp
  src/keywrap.cpp)
set_target_properties(ekicore_primitives PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(ekicore_primitives
  PUBLIC "${PROJECT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(ekicore_primitives PUBLIC OpenSSL::Crypto PRIVATE ekicore_warnings)

# The key store is part of the library only: it includes secret_buffer.hpp, which depends on
# EKI_MLOCK, a definition that the library target carries and the object library does not.
add_library(ekicore SHARED
  src/version.cpp
  src/ffi.cpp
  src/keystore/store.cpp
  src/keystore/software.cpp)
set_target_properties(ekicore PROPERTIES OUTPUT_NAME ekicore)

# The PKCS#11 backend loads its module at run time with dlopen, so no PKCS#11 library is linked;
# it compiles against the vendored interface header, as a system include so that the project's
# warnings and clang-tidy do not apply to it. Without EKI_WITH_PKCS11 the store logic answers
# EKI_KS_PKCS11 with EKI_ERR_UNSUPPORTED and none of this is built.
if(EKI_WITH_PKCS11)
  target_sources(ekicore PRIVATE
    src/keystore/pkcs11.cpp
    src/keystore/pkcs11_module.cpp)
  target_include_directories(ekicore SYSTEM PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/third_party/pkcs11")
  target_link_libraries(ekicore PRIVATE ${CMAKE_DL_LIBS})
endif()

target_include_directories(ekicore
  PUBLIC  "${PROJECT_SOURCE_DIR}/include"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_compile_definitions(ekicore PRIVATE EKI_VERSION_STRING="${PROJECT_VERSION}")
foreach(_eki_option IN ITEMS EKI_WITH_PKCS11 EKI_WITH_PQ EKI_MLOCK)
  if(${_eki_option})
    target_compile_definitions(ekicore PRIVATE ${_eki_option}=1)
  endif()
endforeach()

# Only the eki_* functions are exported: the header marks them EKI_API, everything else is hidden.
# Exceptions stay enabled because the implementation may use them; the extern "C" layer catches them.
foreach(_eki_target IN ITEMS ekicore ekicore_primitives)
  target_compile_options(${_eki_target} PRIVATE
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -fexceptions)
endforeach()

target_link_libraries(ekicore PRIVATE ekicore_primitives ekicore_warnings OpenSSL::Crypto)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT EKI_SANITIZE)
  foreach(_eki_target IN ITEMS ekicore ekicore_primitives)
    target_compile_options(${_eki_target} PRIVATE
      -fstack-protector-strong
      # _FORTIFY_SOURCE needs optimization; glibc warns (and -Werror fails) in unoptimized builds.
      "$<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-U_FORTIFY_SOURCE;-D_FORTIFY_SOURCE=2>")
  endforeach()
  target_link_options(ekicore PRIVATE -Wl,-z,relro,-z,now)
endif()

if(EKI_BUILD_TESTS)
  add_subdirectory(tests)
  # The primitive tests call the internal C++ API directly, so they get their own copy of it.
  target_link_libraries(ekicore_tests PRIVATE ekicore_primitives)
endif()
