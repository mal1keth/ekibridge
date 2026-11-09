#pragma once

// Dual control of destroy (ABI 2 contract section 6): the approver keys of a handle and its pending
// destroy requests. Layer 2 decides every status; this class only holds the data and answers
// lookups. Requests live in the handle and vanish with it.

#include <ekicore.h>
#include <ekicore/keystore.hpp>
#include <ekicore/primitives.hpp>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace ekicore::keystore {

class dual_control {
public:
  using public_key = std::array<std::uint8_t, EKI_P256_PUBLIC_KEY_LEN>;
  using request = std::array<std::uint8_t, EKI_DESTROY_REQUEST_LEN>;

  // How many distinct approvers must approve a request before the key is destroyed.
  static constexpr std::uint32_t approvals_needed = 2;

  // A pending request: its random bytes and the set of approvers that approved it (bit i for
  // approver i of the configuration). Trivially copyable, so a snapshot of one is a plain copy.
  struct pending {
    request value{};
    std::uint8_t approved_by = 0;

    [[nodiscard]] std::uint32_t approvals() const noexcept {
      return static_cast<std::uint32_t>(std::popcount(approved_by));
    }
    [[nodiscard]] bool has_approval_of(std::size_t approver) const noexcept {
      return ((static_cast<unsigned>(approved_by) >> approver) & 1U) != 0;
    }
    void approve(std::size_t approver) noexcept {
      approved_by =
          static_cast<std::uint8_t>(static_cast<unsigned>(approved_by) | (1U << approver));
    }
  };
  static_assert(EKI_APPROVERS_MAX <= 8, "approved_by has one bit per approver");

  // approvers: 2..=EKI_APPROVERS_MAX distinct valid keys, checked by the caller.
  explicit dual_control(std::vector<public_key> approvers) noexcept
      : approvers_(std::move(approvers)) {}

  // The position of key among the approvers, or nullopt when it is not one of them.
  [[nodiscard]] std::optional<std::size_t> approver_index(bytes key) const noexcept;

  // The key id and pending request whose bytes equal value, or nullopt. The comparison is
  // constant time per request.
  [[nodiscard]] std::optional<std::pair<key_id, pending>> find(bytes value) const noexcept;

  // Whether any pending request has these bytes.
  [[nodiscard]] bool in_use(const request& value) const noexcept {
    return find(value).has_value();
  }

  // The pending request for id, or nullopt.
  [[nodiscard]] std::optional<pending> pending_for(const key_id& id) const noexcept;

  // Makes request the pending request for id, replacing any earlier one. May throw (allocation)
  // when id has no request yet; then nothing changes.
  void set(const key_id& id, const pending& request);

  // Removes the pending request for id, if any.
  void remove(const key_id& id) noexcept;

  // Puts back the pending request for id as it was before a change (none: removed). Used to undo
  // a set; never allocates, because the set left an entry for id behind.
  void restore(const key_id& id, const std::optional<pending>& before) noexcept;

private:
  std::vector<public_key> approvers_;
  std::map<key_id, pending> pending_;
};

// The message an approver signs: the 20 ASCII bytes "ekibridge-destroy-v1", the 32 request bytes,
// the 16 key id bytes.
inline constexpr std::size_t approval_message_len = 20 + EKI_DESTROY_REQUEST_LEN + EKI_KEY_ID_LEN;
[[nodiscard]] std::array<std::uint8_t, approval_message_len>
approval_message(const dual_control::request& value, const key_id& id) noexcept;

// Whether key65 is a valid SEC1 uncompressed P-256 point: EKI_OK, EKI_ERR_INVALID_ARGUMENT, or
// EKI_ERR_BACKEND when OpenSSL fails.
[[nodiscard]] eki_status check_public_key(bytes key65) noexcept;

} // namespace ekicore::keystore
