#pragma once

// The process-wide side of the PKCS#11 backend (docs/threat-model.md, "PKCS#11 specifics"):
// loading a module, initialising it, and finalising it when the last handle that uses it closes.
// C_Initialize and the login state belong to the whole process, not to one handle, so they are
// managed here once per module path; each handle holds a module_lease and its own session.
//
// Also the CKR_* names that every BACKEND message carries.

#include <ekicore/keystore.hpp>

#include <pkcs11.h>

#include <string>
#include <string_view>

namespace ekicore::keystore::pkcs11 {

// The name of a PKCS#11 return value ("CKR_PIN_INCORRECT"), or "CKR_0x" and the value in
// hexadecimal for a code outside the table (vendor-defined codes, newer versions).
[[nodiscard]] std::string rv_name(CK_RV rv);

// An EKI_ERR_BACKEND outcome whose detail is "<function> failed: <CKR name>".
[[nodiscard]] outcome failure(std::string_view function, CK_RV rv);

// One handle's claim on an initialised module. While any lease on a module path exists, the module
// stays initialised; when the last one is released, the module is finalised if this library
// initialised it. Movable, not copyable; an empty lease holds nothing.
class module_lease {
public:
  module_lease() = default;
  module_lease(const module_lease&) = delete;
  module_lease& operator=(const module_lease&) = delete;
  module_lease(module_lease&& other) noexcept;
  module_lease& operator=(module_lease&& other) noexcept;
  ~module_lease();

  // Loads module_path (once per process), initialises it if no lease on it exists, and puts a
  // lease on it into lease. Every failure is EKI_ERR_BACKEND and leaves lease empty.
  [[nodiscard]] static outcome acquire(const std::string& module_path, module_lease& lease);

  // The module's function list; null for an empty lease.
  [[nodiscard]] CK_FUNCTION_LIST* functions() const noexcept {
    return functions_;
  }

private:
  void release() noexcept;

  std::string module_path_;
  CK_FUNCTION_LIST* functions_ = nullptr;
};

} // namespace ekicore::keystore::pkcs11
