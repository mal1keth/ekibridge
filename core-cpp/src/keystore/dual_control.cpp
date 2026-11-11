// Dual control of destroy: the approver set and the pending requests of a handle.

#include <ekicore/dual_control.hpp>
#include <ekicore/primitives.hpp>

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace ekicore::keystore {

std::optional<std::size_t> dual_control::approver_index(bytes key) const noexcept {
  const auto found = std::ranges::find_if(
      approvers_, [key](const public_key& approver) { return std::ranges::equal(approver, key); });
  if (found == approvers_.end()) {
    return std::nullopt;
  }
  return static_cast<std::size_t>(found - approvers_.begin());
}

std::optional<std::pair<key_id, dual_control::pending>>
dual_control::find(bytes value) const noexcept {
  if (value.size() != EKI_DESTROY_REQUEST_LEN) {
    return std::nullopt;
  }
  for (const auto& [id, entry] : pending_) {
    if (CRYPTO_memcmp(entry.value.data(), value.data(), value.size()) == 0) {
      return std::pair{id, entry};
    }
  }
  return std::nullopt;
}

std::optional<dual_control::pending> dual_control::pending_for(const key_id& id) const noexcept {
  const auto found = pending_.find(id);
  if (found == pending_.end()) {
    return std::nullopt;
  }
  return found->second;
}

void dual_control::set(const key_id& id, const pending& entry) {
  pending_.insert_or_assign(id, entry);
}

void dual_control::remove(const key_id& id) noexcept {
  pending_.erase(id);
}

void dual_control::restore(const key_id& id, const std::optional<pending>& before) noexcept {
  if (!before.has_value()) {
    pending_.erase(id);
    return;
  }
  const auto found = pending_.find(id);
  if (found != pending_.end()) {
    found->second = *before;
  }
}

std::array<std::uint8_t, approval_message_len> approval_message(const dual_control::request& value,
                                                                const key_id& id) noexcept {
  static constexpr std::string_view domain = "ekibridge-destroy-v1";
  static_assert(domain.size() + EKI_DESTROY_REQUEST_LEN + EKI_KEY_ID_LEN == approval_message_len);
  std::array<std::uint8_t, approval_message_len> message{};
  const std::span<std::uint8_t> out{message};
  std::ranges::transform(domain, out.begin(), [](char c) { return static_cast<std::uint8_t>(c); });
  std::ranges::copy(value, out.subspan(domain.size()).begin());
  std::ranges::copy(id, out.subspan(domain.size() + value.size()).begin());
  return message;
}

eki_status check_public_key(bytes key65) noexcept {
  // ecdsa_p256_verify parses and checks the public key before it looks at the signature, and
  // answers EKI_ERR_INVALID_ARGUMENT for the key alone. With an all-zero signature (r = 0) a valid
  // key then ends at the range check of r with EKI_ERR_AUTH_FAILED, before any verification.
  static constexpr std::array<std::uint8_t, EKI_P256_SIGNATURE_LEN> zero_signature{};
  const eki_status status = ecdsa_p256_verify(key65, {}, zero_signature);
  return status == EKI_ERR_AUTH_FAILED || status == EKI_OK ? EKI_OK : status;
}

} // namespace ekicore::keystore
