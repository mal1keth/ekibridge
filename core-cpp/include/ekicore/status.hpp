#pragma once

#include <ekicore.h>

#include <cstdint>

namespace ekicore {

// Identifier of a status value ("EKI_OK", "EKI_ERR_AUTH_FAILED", ...), or "EKI_STATUS_UNKNOWN" for
// any other integer. Never returns nullptr; the string has static storage.
const char* status_name(std::int32_t status) noexcept;

} // namespace ekicore
