// eki_audit_verify on an arbitrary file, written to a scratch file for each input.
//
// Input: one byte modulo 3 choosing expected_head (NULL; the head of the harness's own reading of
// the file, or 32 zero bytes when that reading rejects it; 32 bytes that follow), then the file's
// bytes, all the rest of the input.
//
// The oracle is ekifuzz::audit_rebuild: an independent, strict reading of the record grammar and
// the hash chain written from the ABI 2 contract. Properties:
// * the status is EKI_OK or EKI_ERR_AUTH_FAILED (the file exists and is readable);
// * the library accepts the file exactly when the rebuild does and expected_head, if given,
//   equals the rebuilt head; it then reports the rebuilt number of records;
// * after a failure records_out is zero.
//
// Mirrors core-rs/fuzz/fuzz_targets/audit_verify.rs.

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <optional>

#include "ekicore.h"
#include "fuzz_input.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ekifuzz::Input in(data, size);
  const unsigned mode = in.u8() % 3U;
  std::optional<ekifuzz::Digest> head;
  if (mode == 2) {
    head = in.array<EKI_AUDIT_HASH_LEN>();
  }
  const ekifuzz::Buffer log = in.rest();
  const std::optional<ekifuzz::AuditHead> rebuilt = ekifuzz::audit_rebuild(log.span());
  if (mode == 1) {
    head = rebuilt ? rebuilt->hash : ekifuzz::Digest{};
  }

  static const ekifuzz::Scratch scratch("audit_verify");
  {
    std::ofstream file(scratch.log, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(log.data()), static_cast<std::streamsize>(log.size()));
    ekifuzz::require(file.good(), "writing the scratch log");
  }
  ekifuzz::Slot<uint64_t> records(false);
  const auto status = static_cast<int32_t>(
      eki_audit_verify(scratch.log.c_str(), head ? head->data() : nullptr, records.ptr()));
  ekifuzz::Call call{"eki_audit_verify", status};
  call.outputs.push_back(records.seen());
  call.check();

  if (rebuilt && (!head || *head == rebuilt->hash)) {
    ekifuzz::expect_status(status, EKI_OK, "eki_audit_verify of a valid log");
    ekifuzz::require(records.get() == rebuilt->records, "wrong record count");
  } else {
    ekifuzz::expect_status(status, EKI_ERR_AUTH_FAILED, "eki_audit_verify of an invalid log");
  }
  return 0;
}
