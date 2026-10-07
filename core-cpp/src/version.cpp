// The metadata entry points of the C ABI, and the status name table they share with the rest of
// the library.

// The public header comes first: its EKI_API attribute has to be on the declarations before the
// definitions below, because the library is built with -fvisibility=hidden.
#include <ekicore.h>

#include <ekicore/status.hpp>

#include <cstdint>

namespace ekicore {

const char* status_name(std::int32_t status) noexcept {
  switch (status) {
  case EKI_OK:
    return "EKI_OK";
  case EKI_ERR_NULL_POINTER:
    return "EKI_ERR_NULL_POINTER";
  case EKI_ERR_INVALID_ARGUMENT:
    return "EKI_ERR_INVALID_ARGUMENT";
  case EKI_ERR_BUFFER_TOO_SMALL:
    return "EKI_ERR_BUFFER_TOO_SMALL";
  case EKI_ERR_UNSUPPORTED:
    return "EKI_ERR_UNSUPPORTED";
  case EKI_ERR_AUTH_FAILED:
    return "EKI_ERR_AUTH_FAILED";
  case EKI_ERR_KEY_NOT_FOUND:
    return "EKI_ERR_KEY_NOT_FOUND";
  case EKI_ERR_KEY_EXISTS:
    return "EKI_ERR_KEY_EXISTS";
  case EKI_ERR_WRONG_KEY_TYPE:
    return "EKI_ERR_WRONG_KEY_TYPE";
  case EKI_ERR_BACKEND:
    return "EKI_ERR_BACKEND";
  case EKI_ERR_INTERNAL:
    return "EKI_ERR_INTERNAL";
  default:
    return "EKI_STATUS_UNKNOWN";
  }
}

} // namespace ekicore

extern "C" {

uint32_t eki_abi_version() {
  return EKI_ABI_VERSION;
}

const char* eki_version() {
  // EKI_VERSION_STRING comes from the CMake project version. Static storage, as the contract
  // requires.
  static constexpr const char* kVersion = "ekicore-cpp " EKI_VERSION_STRING;
  return kVersion;
}

const char* eki_status_name(int32_t status) {
  return ekicore::status_name(status);
}

} // extern "C"
