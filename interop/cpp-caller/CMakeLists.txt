# cpp-caller: C++ "customer code" that uses the ekicore C ABI without linking either library.
# It compiles against include/ekicore.h only and dlopen()s whichever library path it is given, so
# one binary runs against libekicore (C++) and libekicore_rs (Rust) alike.

add_executable(cpp-caller main.cpp)

set_target_properties(cpp-caller PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF)

target_include_directories(cpp-caller PRIVATE "${PROJECT_SOURCE_DIR}/include")

# Same warning set as core-cpp. Repeated here rather than taken from core-cpp's targets, so that
# nothing of the library build leaks into the caller.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(cpp-caller PRIVATE
    -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wsign-conversion)
endif()

# dlopen/dlsym only (libdl on older glibc, part of libc elsewhere). Neither ekicore library is linked.
target_link_libraries(cpp-caller PRIVATE ${CMAKE_DL_LIBS})
