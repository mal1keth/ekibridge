"""Tests of the generated Python module ekicore_uniffi against the built library.

The module and the library it loads come from bindings/uniffi/scripts/generate.sh python, and
scripts/test-python.sh puts that directory on PYTHONPATH. The vectors are the ones in
conformance/vectors/, which name their sources.
"""

import unittest

import ekicore_uniffi as eki
from ekicore_uniffi import AeadAlgorithm, EkiError


def unhex(text: str) -> bytes:
    return bytes.fromhex(text)


# RFC 4231 section 4.3, test case 2.
HMAC_KEY = b"Jefe"
HMAC_MSG = b"what do ya want for nothing?"
HMAC_TAG = unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

# RFC 5869 appendix A.1.
HKDF_IKM = unhex("0b" * 22)
HKDF_SALT = unhex("000102030405060708090a0b0c")
HKDF_INFO = unhex("f0f1f2f3f4f5f6f7f8f9")
HKDF_OKM = unhex(
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
)

# RFC 8439 section 2.8.2.
CHACHA = dict(
    key=unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
    nonce=unhex("070000004041424344454647"),
    aad=unhex("50515253c0c1c2c3c4c5c6c7"),
    pt=unhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a"
        "204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f72207468"
        "65206675747572652c2073756e73637265656e20776f756c642062652069742e"
    ),
    ct=unhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca967128"
        "2fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fa"
        "b324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
    ),
    tag=unhex("1ae10b594f09e26a7e902ecbd0600691"),
)

# The GCM specification (McGrew and Viega), appendix B, test case 16. AES-GCM has no RFC vector
# with a 256-bit key and a 96-bit nonce; this is the one conformance/vectors uses.
GCM = dict(
    key=unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
    nonce=unhex("cafebabefacedbaddecaf888"),
    aad=unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
    pt=unhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532f"
        "cf0e2449a6b525b16aedf5aa0de657ba637b39"
    ),
    ct=unhex(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7"
        "b08b1056828838c5f61e6393ba7a0abcc9f662"
    ),
    tag=unhex("76fc6ece0f4e1768cddf8853bb2d551b"),
)

# RFC 6979 appendix A.2.5: P-256 public key and the SHA-256 signature of "sample".
ECDSA_PUBLIC_KEY = unhex(
    "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
)
ECDSA_MSG = b"sample"
ECDSA_SIG = unhex(
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
)


def flip_first_bit(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


class KnownAnswers(unittest.TestCase):
    def test_hmac_rfc4231(self):
        self.assertEqual(eki.hmac_sha256(HMAC_KEY, HMAC_MSG), HMAC_TAG)
        self.assertIsNone(eki.hmac_sha256_verify(HMAC_KEY, HMAC_MSG, HMAC_TAG))

    def test_hkdf_rfc5869(self):
        okm = eki.hkdf_sha256(HKDF_IKM, HKDF_SALT, HKDF_INFO, len(HKDF_OKM))
        self.assertEqual(okm, HKDF_OKM)

    def test_chacha20_poly1305_rfc8439(self):
        v = CHACHA
        sealed = eki.aead_seal(
            AeadAlgorithm.CHACHA20_POLY1305, v["key"], v["nonce"], v["aad"], v["pt"]
        )
        self.assertEqual(sealed.ciphertext, v["ct"])
        self.assertEqual(sealed.tag, v["tag"])
        pt = eki.aead_open(
            AeadAlgorithm.CHACHA20_POLY1305, v["key"], v["nonce"], v["aad"], v["ct"], v["tag"]
        )
        self.assertEqual(pt, v["pt"])

    def test_aes_256_gcm_spec(self):
        v = GCM
        sealed = eki.aead_seal(AeadAlgorithm.AES256_GCM, v["key"], v["nonce"], v["aad"], v["pt"])
        self.assertEqual(sealed.ciphertext, v["ct"])
        self.assertEqual(sealed.tag, v["tag"])

    def test_ecdsa_p256_rfc6979(self):
        self.assertIsNone(eki.ecdsa_p256_verify(ECDSA_PUBLIC_KEY, ECDSA_MSG, ECDSA_SIG))


class RoundTrips(unittest.TestCase):
    def test_seal_then_open_each_algorithm(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        aad = b"header"
        plaintext = b"attack at dawn"
        for algorithm in AeadAlgorithm:
            with self.subTest(algorithm=algorithm):
                sealed = eki.aead_seal(algorithm, key, nonce, aad, plaintext)
                self.assertEqual(len(sealed.ciphertext), len(plaintext))
                self.assertEqual(len(sealed.tag), 16)
                opened = eki.aead_open(algorithm, key, nonce, aad, sealed.ciphertext, sealed.tag)
                self.assertEqual(opened, plaintext)

    def test_empty_plaintext(self):
        for algorithm in AeadAlgorithm:
            with self.subTest(algorithm=algorithm):
                sealed = eki.aead_seal(algorithm, bytes(32), bytes(12), b"", b"")
                self.assertEqual(sealed.ciphertext, b"")
                opened = eki.aead_open(algorithm, bytes(32), bytes(12), b"", b"", sealed.tag)
                self.assertEqual(opened, b"")


class Errors(unittest.TestCase):
    def assert_raises_status(self, error_class, status_name, call, *args):
        with self.assertRaises(error_class) as raised:
            call(*args)
        self.assertIsInstance(raised.exception, EkiError)
        self.assertEqual(str(raised.exception), status_name)

    def test_invalid_argument(self):
        invalid = EkiError.InvalidArgument
        name = "EKI_ERR_INVALID_ARGUMENT"
        self.assert_raises_status(invalid, name, eki.hmac_sha256, b"", HMAC_MSG)
        self.assert_raises_status(
            invalid, name, eki.hmac_sha256_verify, HMAC_KEY, HMAC_MSG, HMAC_TAG[:31]
        )
        self.assert_raises_status(invalid, name, eki.hkdf_sha256, HKDF_IKM, b"", b"", 0)
        self.assert_raises_status(invalid, name, eki.hkdf_sha256, HKDF_IKM, b"", b"", 8161)
        self.assert_raises_status(invalid, name, eki.hkdf_sha256, b"", b"", b"", 32)
        for algorithm in AeadAlgorithm:
            with self.subTest(algorithm=algorithm):
                self.assert_raises_status(
                    invalid, name, eki.aead_seal, algorithm, bytes(16), bytes(12), b"", b"pt"
                )
                self.assert_raises_status(
                    invalid, name, eki.aead_seal, algorithm, bytes(32), bytes(11), b"", b"pt"
                )
                self.assert_raises_status(
                    invalid, name, eki.aead_open, algorithm, bytes(32), bytes(12), b"", b"ct",
                    bytes(15),
                )
        bad_point = b"\x02" + ECDSA_PUBLIC_KEY[1:]
        self.assert_raises_status(
            invalid, name, eki.ecdsa_p256_verify, bad_point, ECDSA_MSG, ECDSA_SIG
        )

    def test_authentication_failure(self):
        failed = EkiError.AuthFailed
        name = "EKI_ERR_AUTH_FAILED"
        self.assert_raises_status(
            failed, name, eki.hmac_sha256_verify, HMAC_KEY, HMAC_MSG, flip_first_bit(HMAC_TAG)
        )
        v = CHACHA
        for algorithm in AeadAlgorithm:
            with self.subTest(algorithm=algorithm):
                sealed = eki.aead_seal(algorithm, v["key"], v["nonce"], v["aad"], v["pt"])
                args = [algorithm, v["key"], v["nonce"], v["aad"], sealed.ciphertext, sealed.tag]
                for index, label in [(3, "aad"), (4, "ciphertext"), (5, "tag")]:
                    with self.subTest(changed=label):
                        changed = list(args)
                        changed[index] = flip_first_bit(changed[index])
                        self.assert_raises_status(failed, name, eki.aead_open, *changed)
        self.assert_raises_status(
            failed, name, eki.ecdsa_p256_verify, ECDSA_PUBLIC_KEY, b"other", ECDSA_SIG
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
