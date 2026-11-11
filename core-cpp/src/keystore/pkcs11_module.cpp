// The process-wide registry of PKCS#11 modules and the CKR_* names. See pkcs11_module.hpp.

#include "pkcs11_module.hpp"

#include <dlfcn.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace ekicore::keystore::pkcs11 {
namespace {

struct rv_entry {
  CK_RV rv;
  std::string_view name;
};

// The codes a module can return to the calls this library makes (PKCS #11 2.40 and the 3.0
// additions that apply to them). Anything else is printed in hexadecimal.
constexpr auto rv_names = std::to_array<rv_entry>({
    rv_entry{.rv = CKR_OK, .name = "CKR_OK"},
    rv_entry{.rv = CKR_HOST_MEMORY, .name = "CKR_HOST_MEMORY"},
    rv_entry{.rv = CKR_SLOT_ID_INVALID, .name = "CKR_SLOT_ID_INVALID"},
    rv_entry{.rv = CKR_GENERAL_ERROR, .name = "CKR_GENERAL_ERROR"},
    rv_entry{.rv = CKR_FUNCTION_FAILED, .name = "CKR_FUNCTION_FAILED"},
    rv_entry{.rv = CKR_ARGUMENTS_BAD, .name = "CKR_ARGUMENTS_BAD"},
    rv_entry{.rv = CKR_CANT_LOCK, .name = "CKR_CANT_LOCK"},
    rv_entry{.rv = CKR_ATTRIBUTE_READ_ONLY, .name = "CKR_ATTRIBUTE_READ_ONLY"},
    rv_entry{.rv = CKR_ATTRIBUTE_SENSITIVE, .name = "CKR_ATTRIBUTE_SENSITIVE"},
    rv_entry{.rv = CKR_ATTRIBUTE_TYPE_INVALID, .name = "CKR_ATTRIBUTE_TYPE_INVALID"},
    rv_entry{.rv = CKR_ATTRIBUTE_VALUE_INVALID, .name = "CKR_ATTRIBUTE_VALUE_INVALID"},
    rv_entry{.rv = CKR_ACTION_PROHIBITED, .name = "CKR_ACTION_PROHIBITED"},
    rv_entry{.rv = CKR_DATA_INVALID, .name = "CKR_DATA_INVALID"},
    rv_entry{.rv = CKR_DATA_LEN_RANGE, .name = "CKR_DATA_LEN_RANGE"},
    rv_entry{.rv = CKR_DEVICE_ERROR, .name = "CKR_DEVICE_ERROR"},
    rv_entry{.rv = CKR_DEVICE_MEMORY, .name = "CKR_DEVICE_MEMORY"},
    rv_entry{.rv = CKR_DEVICE_REMOVED, .name = "CKR_DEVICE_REMOVED"},
    rv_entry{.rv = CKR_ENCRYPTED_DATA_INVALID, .name = "CKR_ENCRYPTED_DATA_INVALID"},
    rv_entry{.rv = CKR_ENCRYPTED_DATA_LEN_RANGE, .name = "CKR_ENCRYPTED_DATA_LEN_RANGE"},
    rv_entry{.rv = CKR_FUNCTION_NOT_SUPPORTED, .name = "CKR_FUNCTION_NOT_SUPPORTED"},
    rv_entry{.rv = CKR_KEY_HANDLE_INVALID, .name = "CKR_KEY_HANDLE_INVALID"},
    rv_entry{.rv = CKR_KEY_SIZE_RANGE, .name = "CKR_KEY_SIZE_RANGE"},
    rv_entry{.rv = CKR_KEY_TYPE_INCONSISTENT, .name = "CKR_KEY_TYPE_INCONSISTENT"},
    rv_entry{.rv = CKR_KEY_FUNCTION_NOT_PERMITTED, .name = "CKR_KEY_FUNCTION_NOT_PERMITTED"},
    rv_entry{.rv = CKR_KEY_NOT_WRAPPABLE, .name = "CKR_KEY_NOT_WRAPPABLE"},
    rv_entry{.rv = CKR_KEY_UNEXTRACTABLE, .name = "CKR_KEY_UNEXTRACTABLE"},
    rv_entry{.rv = CKR_MECHANISM_INVALID, .name = "CKR_MECHANISM_INVALID"},
    rv_entry{.rv = CKR_MECHANISM_PARAM_INVALID, .name = "CKR_MECHANISM_PARAM_INVALID"},
    rv_entry{.rv = CKR_OBJECT_HANDLE_INVALID, .name = "CKR_OBJECT_HANDLE_INVALID"},
    rv_entry{.rv = CKR_OPERATION_ACTIVE, .name = "CKR_OPERATION_ACTIVE"},
    rv_entry{.rv = CKR_OPERATION_NOT_INITIALIZED, .name = "CKR_OPERATION_NOT_INITIALIZED"},
    rv_entry{.rv = CKR_PIN_INCORRECT, .name = "CKR_PIN_INCORRECT"},
    rv_entry{.rv = CKR_PIN_INVALID, .name = "CKR_PIN_INVALID"},
    rv_entry{.rv = CKR_PIN_LEN_RANGE, .name = "CKR_PIN_LEN_RANGE"},
    rv_entry{.rv = CKR_PIN_EXPIRED, .name = "CKR_PIN_EXPIRED"},
    rv_entry{.rv = CKR_PIN_LOCKED, .name = "CKR_PIN_LOCKED"},
    rv_entry{.rv = CKR_SESSION_CLOSED, .name = "CKR_SESSION_CLOSED"},
    rv_entry{.rv = CKR_SESSION_COUNT, .name = "CKR_SESSION_COUNT"},
    rv_entry{.rv = CKR_SESSION_HANDLE_INVALID, .name = "CKR_SESSION_HANDLE_INVALID"},
    rv_entry{.rv = CKR_SESSION_READ_ONLY, .name = "CKR_SESSION_READ_ONLY"},
    rv_entry{.rv = CKR_SESSION_EXISTS, .name = "CKR_SESSION_EXISTS"},
    rv_entry{.rv = CKR_SIGNATURE_INVALID, .name = "CKR_SIGNATURE_INVALID"},
    rv_entry{.rv = CKR_SIGNATURE_LEN_RANGE, .name = "CKR_SIGNATURE_LEN_RANGE"},
    rv_entry{.rv = CKR_TEMPLATE_INCOMPLETE, .name = "CKR_TEMPLATE_INCOMPLETE"},
    rv_entry{.rv = CKR_TEMPLATE_INCONSISTENT, .name = "CKR_TEMPLATE_INCONSISTENT"},
    rv_entry{.rv = CKR_TOKEN_NOT_PRESENT, .name = "CKR_TOKEN_NOT_PRESENT"},
    rv_entry{.rv = CKR_TOKEN_NOT_RECOGNIZED, .name = "CKR_TOKEN_NOT_RECOGNIZED"},
    rv_entry{.rv = CKR_TOKEN_WRITE_PROTECTED, .name = "CKR_TOKEN_WRITE_PROTECTED"},
    rv_entry{.rv = CKR_UNWRAPPING_KEY_HANDLE_INVALID, .name = "CKR_UNWRAPPING_KEY_HANDLE_INVALID"},
    rv_entry{.rv = CKR_UNWRAPPING_KEY_SIZE_RANGE, .name = "CKR_UNWRAPPING_KEY_SIZE_RANGE"},
    rv_entry{
        .rv = CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        .name = "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
    },
    rv_entry{.rv = CKR_USER_ALREADY_LOGGED_IN, .name = "CKR_USER_ALREADY_LOGGED_IN"},
    rv_entry{.rv = CKR_USER_NOT_LOGGED_IN, .name = "CKR_USER_NOT_LOGGED_IN"},
    rv_entry{.rv = CKR_USER_PIN_NOT_INITIALIZED, .name = "CKR_USER_PIN_NOT_INITIALIZED"},
    rv_entry{.rv = CKR_USER_TYPE_INVALID, .name = "CKR_USER_TYPE_INVALID"},
    rv_entry{
        .rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
        .name = "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
    },
    rv_entry{.rv = CKR_WRAPPED_KEY_INVALID, .name = "CKR_WRAPPED_KEY_INVALID"},
    rv_entry{.rv = CKR_WRAPPED_KEY_LEN_RANGE, .name = "CKR_WRAPPED_KEY_LEN_RANGE"},
    rv_entry{.rv = CKR_WRAPPING_KEY_HANDLE_INVALID, .name = "CKR_WRAPPING_KEY_HANDLE_INVALID"},
    rv_entry{.rv = CKR_WRAPPING_KEY_SIZE_RANGE, .name = "CKR_WRAPPING_KEY_SIZE_RANGE"},
    rv_entry{
        .rv = CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
        .name = "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
    },
    rv_entry{.rv = CKR_RANDOM_NO_RNG, .name = "CKR_RANDOM_NO_RNG"},
    rv_entry{.rv = CKR_DOMAIN_PARAMS_INVALID, .name = "CKR_DOMAIN_PARAMS_INVALID"},
    rv_entry{.rv = CKR_CURVE_NOT_SUPPORTED, .name = "CKR_CURVE_NOT_SUPPORTED"},
    rv_entry{.rv = CKR_BUFFER_TOO_SMALL, .name = "CKR_BUFFER_TOO_SMALL"},
    rv_entry{.rv = CKR_INFORMATION_SENSITIVE, .name = "CKR_INFORMATION_SENSITIVE"},
    rv_entry{.rv = CKR_CRYPTOKI_NOT_INITIALIZED, .name = "CKR_CRYPTOKI_NOT_INITIALIZED"},
    rv_entry{.rv = CKR_CRYPTOKI_ALREADY_INITIALIZED, .name = "CKR_CRYPTOKI_ALREADY_INITIALIZED"},
    rv_entry{.rv = CKR_MUTEX_BAD, .name = "CKR_MUTEX_BAD"},
});

// A loaded module. The library handle is never closed (see registry::load).
struct loaded_module {
  void* library = nullptr;
  CK_FUNCTION_LIST* functions = nullptr;
  bool we_initialized = false;
  std::size_t open_handles = 0;
};

// The registry: module path -> loaded module, behind one mutex. The mutex is held while a module
// is loaded, initialised or finalised, so two handles opening or closing at the same time agree on
// which of them initialises and which finalises.
class registry {
public:
  outcome acquire(const std::string& module_path, CK_FUNCTION_LIST*& functions) {
    const std::scoped_lock lock{mutex_};
    // The entry is made before anything is loaded, so that a failed allocation leaves no library
    // loaded and unrecorded; a failed load removes the entry again.
    const auto [entry, inserted] = modules_.try_emplace(module_path);
    if (inserted) {
      outcome loaded = load(module_path, entry->second);
      if (loaded.status != EKI_OK) {
        modules_.erase(entry);
        return loaded;
      }
    }
    loaded_module& module = entry->second;
    if (module.open_handles == 0) {
      outcome initialized = initialize(module);
      if (initialized.status != EKI_OK) {
        return initialized;
      }
    }
    ++module.open_handles;
    functions = module.functions;
    return {};
  }

  // Ends one lease. When it was the last one, the module is finalised if this library initialised
  // it; another component that initialised it first keeps it initialised. Taking the lock is the
  // only step that can throw; if it does, the count is not decremented and the module stays
  // initialised, which is safe.
  void release(const std::string& module_path) noexcept {
    try {
      const std::scoped_lock lock{mutex_};
      const auto entry = modules_.find(module_path);
      if (entry == modules_.end() || entry->second.open_handles == 0) {
        return;
      }
      loaded_module& module = entry->second;
      --module.open_handles;
      if (module.open_handles == 0 && module.we_initialized) {
        // Nothing useful can be done when finalisation fails: the next acquire initialises again.
        static_cast<void>(module.functions->C_Finalize(nullptr));
        module.we_initialized = false;
      }
    } catch (...) {
      return;
    }
  }

private:
  // Loads the module and fetches its function list. The library is opened with RTLD_LOCAL, so its
  // symbols do not leak into the process, and it is never closed: after C_Finalize a module may
  // still have threads or exit handlers that run its code (SoftHSM2 registers static destructors),
  // another component may hold function pointers into it, and the second ekicore library in the
  // same process may use the same module. Keeping it mapped costs one library per path for the
  // life of the process.
  static outcome load(const std::string& module_path, loaded_module& module) {
    void* library = ::dlopen(module_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (library == nullptr) {
      return dl_failure("dlopen");
    }
    void* symbol = ::dlsym(library, "C_GetFunctionList");
    if (symbol == nullptr) {
      outcome missing = dl_failure("dlsym C_GetFunctionList");
      ::dlclose(library);
      return missing;
    }
    // POSIX guarantees that dlsym's result converts to the function pointer it names.
    const auto get_function_list = reinterpret_cast<CK_C_GetFunctionList>(symbol);
    CK_FUNCTION_LIST* functions = nullptr;
    const CK_RV rv = get_function_list(&functions);
    if (rv != CKR_OK) {
      ::dlclose(library);
      return failure("C_GetFunctionList", rv);
    }
    if (functions == nullptr) {
      ::dlclose(library);
      return outcome{.status = EKI_ERR_BACKEND, .detail = "C_GetFunctionList returned no list"};
    }
    module.library = library;
    module.functions = functions;
    return {};
  }

  // C_Initialize with the operating system's locking (CKF_OS_LOCKING_OK). A module that another
  // component of the process initialised first answers CKR_CRYPTOKI_ALREADY_INITIALIZED; it is
  // used as it is and never finalised by this library.
  static outcome initialize(loaded_module& module) {
    CK_C_INITIALIZE_ARGS args{};
    args.flags = CKF_OS_LOCKING_OK;
    const CK_RV rv = module.functions->C_Initialize(&args);
    if (rv == CKR_OK) {
      module.we_initialized = true;
      return {};
    }
    if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
      module.we_initialized = false;
      return {};
    }
    return failure("C_Initialize", rv);
  }

  static outcome dl_failure(std::string_view function) {
    const char* reason = ::dlerror();
    outcome result{.status = EKI_ERR_BACKEND, .detail = std::string{function}};
    result.detail += " failed: ";
    result.detail += reason == nullptr ? "no reason given" : reason;
    return result;
  }

  std::mutex mutex_;
  std::map<std::string, loaded_module> modules_;
};

// The registry lives as long as the process and is never destroyed, like the modules it holds: a
// handle may still be closed from an exit handler or a static destructor that runs after this
// translation unit's statics are gone.
registry& the_registry() {
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): deliberately never freed (see above)
  static auto* const instance = new registry;
  return *instance;
}

} // namespace

std::string rv_name(CK_RV rv) {
  const auto* const known =
      std::ranges::find_if(rv_names, [rv](const rv_entry& entry) { return entry.rv == rv; });
  if (known != rv_names.end()) {
    return std::string{known->name};
  }
  static constexpr std::string_view digits = "0123456789ABCDEF";
  std::string hex;
  for (CK_RV rest = rv; rest != 0 || hex.size() < 8; rest >>= 4U) {
    hex.insert(hex.begin(), digits.at(static_cast<std::size_t>(rest & 0xFU)));
  }
  return "CKR_0x" + hex;
}

outcome failure(std::string_view function, CK_RV rv) {
  outcome result{.status = EKI_ERR_BACKEND, .detail = std::string{function}};
  result.detail += " failed: ";
  result.detail += rv_name(rv);
  return result;
}

module_lease::module_lease(module_lease&& other) noexcept
    : module_path_(std::move(other.module_path_)),
      functions_(std::exchange(other.functions_, nullptr)) {}

module_lease& module_lease::operator=(module_lease&& other) noexcept {
  if (this != &other) {
    release();
    module_path_ = std::move(other.module_path_);
    functions_ = std::exchange(other.functions_, nullptr);
  }
  return *this;
}

module_lease::~module_lease() {
  release();
}

outcome module_lease::acquire(const std::string& module_path, module_lease& lease) {
  // dlopen("") would return the main program rather than fail.
  if (module_path.empty()) {
    return outcome{.status = EKI_ERR_BACKEND, .detail = "the module path is empty"};
  }
  // The path is copied first: once the registry has counted the lease, nothing may throw.
  std::string path = module_path;
  CK_FUNCTION_LIST* functions = nullptr;
  outcome result = the_registry().acquire(path, functions);
  if (result.status != EKI_OK) {
    return result;
  }
  lease = module_lease{};
  lease.module_path_ = std::move(path);
  lease.functions_ = functions;
  return {};
}

void module_lease::release() noexcept {
  if (functions_ != nullptr) {
    the_registry().release(module_path_);
    functions_ = nullptr;
  }
}

} // namespace ekicore::keystore::pkcs11
