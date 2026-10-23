#pragma once

// The pieces every extern "C" function of libekicore is assembled from: an exception barrier that
// also zero-fills the outputs on failure, and the conversion of raw (pointer, length) parameters
// into spans under the pointer rule of the ABI contract.
//
// An entry point has this shape:
//
//   const std::array outputs{fixed_output(out, EKI_HMAC_SHA256_LEN)};
//   return ffi_barrier(outputs, [&] {
//     const auto key_span = sized_span(key, key_len);
//     const auto msg_span = sized_span(msg, msg_len);
//     const auto out_span = fixed_span(out, EKI_HMAC_SHA256_LEN);
//     if (!key_span || !msg_span || !out_span) {
//       return EKI_ERR_NULL_POINTER;
//     }
//     return hmac_sha256(*key_span, *msg_span, *out_span);
//   });
//
// The outputs are described before the barrier runs, from the raw parameters alone, so that they
// are zero-filled whatever ends the call: a NULL in another parameter, an error status from the
// primitive, or an exception. Nothing here allocates or throws.

#include <ekicore.h>
#include <ekicore/openssl_raii.hpp>
#include <ekicore/primitives.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <type_traits>

namespace ekicore {

// A parameter whose size is given by a length parameter, input or output. len == 0 gives an empty
// span whose data() is null, so ptr is never read even when it is NULL or dangling; len > 0 with a
// NULL ptr gives std::nullopt, which the entry point reports as EKI_ERR_NULL_POINTER.
// The span is built from the declared length without reading memory, and the primitive rejects an
// out-of-range length before any access, so a declared length larger than the buffer is never
// dereferenced when it is outside the valid range.
template <typename T>
[[nodiscard]] std::optional<std::span<T>> sized_span(T* ptr, std::size_t len) noexcept {
  if (len == 0) {
    return std::span<T>{};
  }
  if (ptr == nullptr) {
    return std::nullopt;
  }
  return std::span<T>{ptr, len};
}

// A fixed-size parameter (tag, public key, signature, fixed output): NULL is an error whatever
// the other arguments are.
template <typename T>
[[nodiscard]] std::optional<std::span<T>> fixed_span(T* ptr, std::size_t len) noexcept {
  if (ptr == nullptr) {
    return std::nullopt;
  }
  return std::span<T>{ptr, len};
}

// The bytes of a fixed-size output that the barrier zero-fills on failure: all of them, or none
// when the pointer is NULL.
[[nodiscard]] inline mut_bytes fixed_output(std::uint8_t* ptr, std::size_t len) noexcept {
  return ptr == nullptr ? mut_bytes{} : mut_bytes{ptr, len};
}

// The bytes of an output sized by a length parameter that the barrier zero-fills on failure. A
// length above MaxLen is outside the valid range and the buffer is left untouched: nothing says
// the caller's buffer is that large.
template <std::size_t MaxLen>
[[nodiscard]] mut_bytes sized_output(std::uint8_t* ptr, std::size_t len) noexcept {
  return ptr == nullptr || len > MaxLen ? mut_bytes{} : mut_bytes{ptr, len};
}

// Runs body and returns its status; any exception, of any type, becomes EKI_ERR_INTERNAL instead
// of unwinding into the C caller. On every status other than EKI_OK each span in outputs is
// zero-filled, including after an exception that interrupted a partial write.
template <typename Body>
  requires std::same_as<std::invoke_result_t<const Body&>, eki_status>
[[nodiscard]] eki_status ffi_barrier(std::span<const mut_bytes> outputs,
                                     const Body& body) noexcept {
  eki_status status = EKI_ERR_INTERNAL;
  try {
    status = body();
  } catch (...) {
    status = EKI_ERR_INTERNAL;
  }
  if (status != EKI_OK) {
    for (const mut_bytes output : outputs) {
      ossl::cleanse(output);
    }
  }
  return status;
}

// The barrier for a function without outputs.
template <typename Body>
  requires std::same_as<std::invoke_result_t<const Body&>, eki_status>
[[nodiscard]] eki_status ffi_barrier(const Body& body) noexcept {
  return ffi_barrier({}, body);
}

} // namespace ekicore
