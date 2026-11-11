# A step-ca CA with its keys in a PKCS#11 token

Certificates, a CA, CRLs and OCSP are deliberately outside the ekibridge library. This note
records a run of [`scripts/stepca-demo.sh`](../scripts/stepca-demo.sh), which puts a step-ca
certificate authority on top of the same kind of PKCS#11 token the library's key store uses, and
says what that run shows about key protection and revocation.

It is a reproducible demonstration on one machine with a software token. It does not show how to
deploy step-ca, it does not evaluate step-ca's security, and it is no evidence about any hardware
HSM.

All eight steps of the script passed: token, CA keys, CA certificates, step-ca start, leaf issue,
revocation with CRL, key attributes, stop. I ran it twice with the same result. There is one
substitution. The root and intermediate certificates are signed with OpenSSL and the libp11
provider instead of the step CLI, because the step CLI needs `step-kms-plugin` for that and
`step-kms-plugin` is not in homebrew-core (see [Not demonstrated](#not-demonstrated)).

## Setup as run

The run was on macOS 26.2 (Darwin 25.2.0, arm64) on 2026-11-11. Everything comes from
homebrew-core except `jq` and `curl`, which ship with macOS.

| Tool | Version | Role |
|---|---|---|
| SoftHSM2 (`softhsm`) | 2.7.0 | PKCS#11 token |
| OpenSC (`opensc`) | 0.27.1 | `pkcs11-tool`: key generation, attribute listing |
| `step` formula | step 0.31.0, step-ca 0.30.2 | the formula builds both binaries; step-ca is built with `CGO_ENABLED=1` on macOS |
| `libp11` | 0.4.21 | `pkcs11prov`, an OpenSSL provider for PKCS#11 keys |
| OpenSSL (`openssl@4`) | 4.1.0 | signs the CA certificates through `pkcs11prov` (which links `libcrypto.4`) |
| OpenSSL (`openssl@3`) | 3.5.9 | every check: `verify`, `crl`, `x509` |
| jq, curl | 1.7.1, 8.7.1 | ca.json, CRL download |

Run it with `scripts/stepca-demo.sh` (add `--keep` to keep the work directory). The script works
in a fresh `mktemp -d` directory and points `SOFTHSM2_CONF` and `STEPPATH` into it, so neither
`~/.step` nor the repository's `.softhsm` token is touched. It stops step-ca and removes the
directory on every exit path. PINs and the provisioner password are random per run.

These are the commands that do the work, as they appear in the script. Most output redirections
are left out, and so are the checks the script runs between them. `$work` is the work directory
and `$label` is `stepca-demo`.

```sh
# 1. token
softhsm2-util --init-token --free --label "$label" --pin "$pin" --so-pin "$so_pin"
# 2. keys (p11 = pkcs11-tool --module "$SOFTHSM2_MODULE" --token-label "$label" --login --pin "$pin")
p11 --keypairgen --key-type EC:prime256v1 --usage-sign --id 01 --label root-ca
p11 --keypairgen --key-type EC:prime256v1 --usage-sign --id 02 --label intermediate-ca
# 3. certs (ossl_p11 = OpenSSL 4 with OPENSSL_CONF loading pkcs11prov and SoftHSM2)
ossl_p11 req -new -x509 -key "$root_key" -subj "/CN=stepca-demo Root CA" -days 3650 -sha256 \
  -config "$work/ca-ext.cnf" -extensions root -set_serial "0x$("$OPENSSL_BIN" rand -hex 16)" \
  -out "$work/root.crt"
ossl_p11 req -new -key "$int_key" -subj "/CN=stepca-demo Intermediate CA" -config "$work/ca-ext.cnf" \
  -out "$work/intermediate.csr"
ossl_p11 x509 -req -in "$work/intermediate.csr" -CA "$work/root.crt" -CAkey "$root_key" -days 1825 \
  -sha256 -extfile "$work/ca-ext.cnf" -extensions intermediate \
  -set_serial "0x$("$OPENSSL_BIN" rand -hex 16)" -out "$work/intermediate.crt"
# 4. ca: ca.json written with jq (excerpt below), then
step-ca "$STEPPATH/config/ca.json" >"$work/logs/step-ca.log" 2>&1 &
# 5. leaf
step ca certificate --provisioner demo-admin --provisioner-password-file "$work/provisioner.pw" \
  --ca-url "$ca_url" --root "$work/root.crt" \
  leaf.demo.test "$work/leaf.crt" "$work/leaf.key"
# 6. revoke, then fetch and read the CRL
token=$(step ca token --revoke --provisioner demo-admin \
  --provisioner-password-file "$work/provisioner.pw" --ca-url "$ca_url" --root "$work/root.crt" \
  "$serial_dec" 2>>"$work/logs/revoke.log")
step ca revoke --token "$token" --ca-url "$ca_url" --root "$work/root.crt" \
  --reason "test-only demo revocation" "$serial_dec"
"$OPENSSL_BIN" crl -inform DER -in "$work/crl.der" -noout -text
# 7. attrs
p11 --list-objects --type privkey
```

Here `$root_key` is `pkcs11:token=stepca-demo;object=root-ca;type=private`, and `$int_key` is the
same URI with `object=intermediate-ca`. This is the part of ca.json that makes step-ca sign with
the token (the PIN sits in the URI as `pin-value`):

```json
"key": "pkcs11:id=02;object=intermediate-ca",
"kms": {"type": "pkcs11", "uri": "pkcs11:module-path=<libsofthsm2.so>;token=stepca-demo?pin-value=<pin>"},
"crl": {"enabled": true, "generateOnRevoke": true, "idpURL": "https://127.0.0.1:<port>/1.0/crl"},
```

The JWK provisioner key is made with `step crypto jwk create` and placed in ca.json with jq.

## What was observed

These are excerpts from one run. Ports and serials differ from run to run.

```
PASS  certs   root and intermediate certificates signed with the token keys
        intermediate.crt: OK
        root.crt public key = token object id=01 (sha256 beb02a99ff56f22f...)
        intermediate.crt public key = token object id=02 (sha256 9d4640856507eb20...)
PASS  ca      step-ca running at https://127.0.0.1:24041, signing with the token key (health: ok)
        files under the work directory containing a PEM private key: 0
PASS  leaf    leaf certificate issued by step-ca; chain verifies
        notBefore=Nov 11 12:32:09 2026 GMT
        notAfter=Nov 12 12:33:09 2026 GMT
        leaf carries no CRL distribution point extension
        leaf.crt: OK
PASS  revoke  leaf serial 55E1012359951684822083CC7CCA7C50 listed in the CRL served by step-ca
        GET /1.0/crl -> HTTP 200, application/pkix-crl
        Last Update: Nov 11 12:33:10 2026 GMT
        Next Update: Nov 12 12:33:10 2026 GMT
        Serial Number: 55E1012359951684822083CC7CCA7C50
        CRL signature: verify OK
        step ca renew of the revoked leaf: The request lacked necessary authorization to be completed. ...
        INFO openssl verify -crl_check: error 44 at 0 depth lookup: different CRL scope
PASS  attrs   CA private keys are token objects: sensitive, never extractable, generated on the token
        Usage:      decrypt, sign, signRecover, unwrap
        Access:     sensitive, always sensitive, never extractable, local
```

- The token generated both CA key pairs (`local`), and the private halves were never extractable.
  The public key in each certificate equals the public key object in the token, so the chain
  `leaf -> intermediate -> root` that `openssl verify` accepts was signed by token keys.
- Before the leaf was requested, no file in the work directory contained a PEM private key. The
  leaf key itself is a software key that the step CLI wrote to `leaf.key`; only the CA keys are in
  the token.
- step-ca issued a leaf valid for 24 hours (its default) and served a DER CRL at `/1.0/crl`,
  signed by the intermediate key through PKCS#11, with its next update 24 hours ahead. With
  `generateOnRevoke` the revoked serial was in the CRL at once. Renewing the revoked leaf failed.
- OpenSSL's own CRL check (`verify -crl_check`) did not accept this CRL for this leaf and reported
  "different CRL scope". The CRL carries a critical Issuing Distribution Point and the leaf has no
  CRL Distribution Point. That mismatch is the likely cause; I did not investigate it further. A
  relying party that checks CRLs with OpenSSL would need leaves that name the CRL (a certificate
  template) or a different CRL setup. Neither was tried.

## How the key protection maps to the library

### The same objects with the same attributes

The CA keys and the library's ECDSA keys are both token objects in a PKCS#11 token (SoftHSM2 here
and in the library's tests). The library generates an ECDSA private key with `CKA_TOKEN`,
`CKA_PRIVATE`, `CKA_SIGN` and `CKA_SENSITIVE` TRUE and `CKA_EXTRACTABLE` FALSE. The listing above
shows the CA keys with the same protection, and with `CKA_ALWAYS_SENSITIVE`,
`CKA_NEVER_EXTRACTABLE` and `CKA_LOCAL` set by the token. These attributes mean the same thing for
both: the module will sign with the key and will not hand out its value.

Neither template clears `CKA_DECRYPT` or `CKA_UNWRAP`, which SoftHSM2 sets TRUE by default. They
grant nothing for an EC key here, but a stricter template would set them FALSE.

### Two meanings of "revoked"

A revoked certificate is a statement by the CA, published in a CRL. Nothing changes in the token:
the leaf's key still signs, and the certificate still verifies for any relying party that does not
check the CRL.

A REVOKED key in ABI 2 is a token state: `CKA_SIGN` FALSE on the private object and `CKA_VERIFY`
FALSE on the public object, set with `C_SetAttributeValue`. The token then refuses to sign.
Applied to the intermediate key, that would stop step-ca from issuing certificates and also from
signing new CRLs, so revocation information would go stale while the certificates already issued
stay valid. How step-ca behaves with a key whose `CKA_SIGN` is FALSE was not demonstrated.

### What the audit log would and would not record

The ABI 2 audit log records `eki_ks_*` calls made through one library handle (generate, rotate,
revoke, destroy, sign and so on, with key ids and status). It would record nothing that step-ca,
`pkcs11-tool` or OpenSSL do in the token through their own PKCS#11 sessions. Certificate issuance,
CRL signing and certificate revocation leave no record there, and SoftHSM2 itself writes
diagnostic messages (`log.level`), which are not an audit record. Only operations performed
through the library would appear.

The library and step-ca sharing one token was not run. The CA keys here use 1-byte `CKA_ID`s,
while the library gives its keys 16-byte ids.

## Revocation in step-ca

This section rests on step-ca's [production guide][prod], [configuration reference][conf] and
[cryptographic protection page][kms], read on 2026-11-11, and on the installed binaries.

step-ca serves a CRL when `"crl": {"enabled": true}` is set. The configuration reference marks CRL
support as experimental, with `generateOnRevoke` and the 24-hour `cacheDuration` as options. The
CRL is served at `/1.0/crl`; the run got HTTP 200 and `application/pkix-crl` from it.

Revocation is passive by default, according to step-ca's production documentation: a revoked
certificate can no longer be renewed but stays valid until it expires. The `step ca revoke --help`
text of the installed step 0.31.0 explains both kinds and does not say which one is the default.
The design leans on short-lived certificates (the observed 24-hour default), so that a
certificate that cannot be renewed soon stops working.

step-ca has no OCSP responder of its own. Its documentation points to commercial offerings for
OCSP. An OCSP deployment, which was not run, would add four things:

- a separate OCSP responder fed with step-ca's revocation data,
- a delegated OCSP signing certificate (extended key usage `OCSPSigning`) issued by the
  intermediate, with its key preferably in the same token,
- an Authority Information Access OCSP URL in the leaf template,
- monitoring that the responder's answers stay fresh.

## Limits of the demonstration

- SoftHSM2 is software. Its "never extractable" is enforced by the SoftHSM2 library inside the
  calling process, on the same machine, with the token's object files in the work directory. A
  hardware HSM enforces the same attributes inside its own boundary.
- The token is a throwaway, created and destroyed per run. There is no backup, key ceremony, split
  knowledge or M-of-N activation of the CA keys.
- Everything runs on one machine, and the root key is online during the run, which a real
  deployment would avoid.
- PINs are in files and URIs: `pin-value` in ca.json and `pin` in the OpenSSL provider
  configuration. They are also on the `softhsm2-util` and `pkcs11-tool` command lines. step offers
  `pin-source` as well; it was not used.
- The token enforces no policy. Nothing in it limits which certificates the intermediate key
  signs, how often, or for whom. That policy lives in step-ca's configuration only.
- I did not examine step-ca's request logging, its database or its TLS server key handling.

## Not demonstrated

- The step CLI did not sign the CA certificates. `step certificate create --kms` with a `pkcs11:`
  key failed in every run with `failed to get public key: exec: "step-kms-plugin": executable file
  not found in $PATH` (printed as INFO in step 3). `step-kms-plugin` is not in homebrew-core
  (`brew info step-kms-plugin`: no such formula), so OpenSSL with libp11 signs them instead.
  step-ca itself needs no plugin: it signs through the `pkcs11` KMS compiled into the Homebrew
  build.
- The run above is macOS only. The Homebrew formula sets `CGO_ENABLED=0` on Linux, and step-ca's
  documentation states that the standard binary does not support PKCS #11 (a CGO build or the
  `hsm` Docker image is needed).
- Four things are described above and were not run: OCSP, a CRL that OpenSSL's `-crl_check`
  accepts, a revoked CA key, and the library and step-ca sharing one token.

[prod]: https://smallstep.com/docs/step-ca/certificate-authority-server-production/
[conf]: https://smallstep.com/docs/step-ca/configuration/
[kms]: https://smallstep.com/docs/step-ca/cryptographic-protection/
