#!/usr/bin/env bash
# Runs a step-ca certificate authority whose root and intermediate private keys are generated in,
# and stay in, a throwaway SoftHSM2 token. Companion to docs/pki-note.md.
#
#   scripts/stepca-demo.sh          run, then remove the work directory
#   scripts/stepca-demo.sh --keep   run, keep the work directory and print its path
#
# Steps, one PASS or FAIL line each (steps after a failure are reported as NOT RUN):
#   1. token     private SoftHSM2 token in a work directory of its own (own softhsm2.conf)
#   2. keys      root and intermediate EC P-256 key pairs generated inside the token (pkcs11-tool)
#   3. certs     root and intermediate certificates signed inside the token (OpenSSL 4 + libp11
#                provider, because the step CLI needs step-kms-plugin for this; see the note)
#   4. ca        step-ca started on 127.0.0.1, signing through its pkcs11 KMS with the intermediate key
#   5. leaf      leaf certificate issued by step-ca, chain checked with openssl verify
#   6. revoke    leaf revoked through step-ca, serial found in the CRL step-ca serves
#   7. attrs     CA private keys listed by pkcs11-tool as sensitive and never extractable
#   8. stop      step-ca stopped
#
# Nothing outside the work directory is written: SOFTHSM2_CONF and STEPPATH point into it, so
# neither ~/.step nor the repository's .softhsm token is touched. The CA is stopped and the work
# directory removed on every exit path (unless --keep, which still stops the CA).
#
# TEST ONLY: the token PINs and the provisioner password are random values generated per run and
# written into the work directory. They protect nothing real.
#
# Tool locations can be overridden: SOFTHSM2_MODULE, PKCS11_PROVIDER (libp11 pkcs11prov),
# OPENSSL_P11 (the openssl binary the provider is built against), OPENSSL_BIN (used for checks).

set -euo pipefail

keep=0
case "${1:-}" in
  "") ;;
  --keep) keep=1 ;;
  -h | --help)
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "usage: $0 [--keep]" >&2
    exit 2
    ;;
esac

# ---- tools -------------------------------------------------------------------------------------

brew_prefix() { brew --prefix "$1" 2>/dev/null || echo "/opt/homebrew/opt/$1"; }

SOFTHSM2_MODULE=${SOFTHSM2_MODULE:-$(brew_prefix softhsm)/lib/softhsm/libsofthsm2.so}
PKCS11_PROVIDER=${PKCS11_PROVIDER:-$(brew_prefix libp11)/lib/ossl-modules/pkcs11prov.dylib}
OPENSSL_P11=${OPENSSL_P11:-$(brew_prefix openssl@4)/bin/openssl}
OPENSSL_BIN=${OPENSSL_BIN:-$(brew_prefix openssl@3)/bin/openssl}

missing=0
for tool in softhsm2-util pkcs11-tool opensc-tool step step-ca jq curl nc "$OPENSSL_P11" "$OPENSSL_BIN"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing tool: $tool" >&2
    missing=1
  fi
done
for file in "$SOFTHSM2_MODULE" "$PKCS11_PROVIDER"; do
  if [ ! -f "$file" ]; then
    echo "missing file: $file" >&2
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then exit 1; fi

# ---- work directory, test-only secrets, cleanup ------------------------------------------------

tmp_root=${TMPDIR:-/tmp}
work=$(mktemp -d "${tmp_root%/}/stepca-demo.XXXXXX")
mkdir -p "$work/logs"
export SOFTHSM2_CONF="$work/softhsm2.conf"
export STEPPATH="$work/step"

label=stepca-demo
pin=$("$OPENSSL_BIN" rand -hex 8)    # TEST ONLY, per run
so_pin=$("$OPENSSL_BIN" rand -hex 8) # TEST ONLY, per run
"$OPENSSL_BIN" rand -hex 16 >"$work/provisioner.pw" # TEST ONLY, per run
echo "$pin" >"$work/user.pin"                     # kept for --keep inspection only
ca_pid=""
ca_url=""

steps=(token keys certs ca leaf revoke attrs stop)
current=""
passed=0

stop_ca() {
  if [ -n "$ca_pid" ] && kill -0 "$ca_pid" 2>/dev/null; then
    kill "$ca_pid" 2>/dev/null || true
    wait "$ca_pid" 2>/dev/null || true
  fi
  ca_pid=""
}

on_exit() {
  local rc=$?
  set +e
  if [ "$rc" -ne 0 ] && [ -n "$current" ]; then
    printf 'FAIL  %-7s (exit %d; last lines of %s)\n' "$current" "$rc" "logs/$current.log"
    tail -n 8 "$work/logs/$current.log" 2>/dev/null | sed 's/^/        | /'
    local seen=0 s
    for s in "${steps[@]}"; do
      if [ "$seen" -eq 1 ]; then printf 'NOT RUN %s\n' "$s"; fi
      if [ "$s" = "$current" ]; then seen=1; fi
    done
    printf 'RESULT: %d PASS, 1 FAIL, %d NOT RUN\n' "$passed" "$((${#steps[@]} - passed - 1))"
  fi
  stop_ca
  if [ "$keep" -eq 1 ]; then
    echo "work directory kept: $work"
  else
    rm -rf "$work"
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

begin() {
  current=$1
  : >"$work/logs/$current.log"
}

pass() {
  printf 'PASS  %-7s %s\n' "$current" "$1"
  passed=$((passed + 1))
  current=""
}

# Evidence lines printed under a PASS line.
show() { sed 's/^/        /'; }

# pkcs11-tool against the demo token, logged in.
p11() { pkcs11-tool --module "$SOFTHSM2_MODULE" --token-label "$label" --login --pin "$pin" "$@"; }

# OpenSSL with the libp11 provider loaded; its diagnostics go to the step log.
ossl_p11() { OPENSSL_CONF="$work/openssl-p11.cnf" "$OPENSSL_P11" "$@" >>"$work/logs/$current.log" 2>&1; }

pubkey_der_sha256() { "$OPENSSL_BIN" pkey -pubin -outform DER | shasum -a 256 | cut -d' ' -f1; }

echo "work directory: $work"
echo "versions: $(softhsm2-util --version | head -n 1) (softhsm2-util); $(opensc-tool --info 2>/dev/null | head -n 1 | cut -d' ' -f1-2)"
echo "          $("$OPENSSL_P11" version) (signing, with libp11 provider)"
echo "          $("$OPENSSL_BIN" version) (checks)"
echo "          $(step version | head -n 1); $(step-ca version | head -n 1)"

# ---- 1. token ----------------------------------------------------------------------------------

begin token
mkdir -p "$work/tokens"
cat >"$SOFTHSM2_CONF" <<CONF
directories.tokendir = $work/tokens
objectstore.backend = file
log.level = ERROR
CONF
softhsm2-util --init-token --free --label "$label" --pin "$pin" --so-pin "$so_pin" >>"$work/logs/token.log" 2>&1
softhsm2-util --show-slots >"$work/slots.txt" 2>>"$work/logs/token.log"
tokens_found=$(grep -Ec "Label:[[:space:]]+${label}[[:space:]]*\$" "$work/slots.txt")
[ "$tokens_found" -eq 1 ]
pass "token '$label' initialised under the work directory (SOFTHSM2_CONF=$SOFTHSM2_CONF)"

# ---- 2. keys -----------------------------------------------------------------------------------

begin keys
p11 --keypairgen --key-type EC:prime256v1 --usage-sign --id 01 --label root-ca >>"$work/logs/keys.log" 2>&1
p11 --keypairgen --key-type EC:prime256v1 --usage-sign --id 02 --label intermediate-ca >>"$work/logs/keys.log" 2>&1
[ "$(p11 --list-objects --type privkey 2>/dev/null | grep -c '^Private Key Object')" -eq 2 ]
pass "EC P-256 key pairs generated in the token: id=01 root-ca, id=02 intermediate-ca"

# ---- 3. certs ----------------------------------------------------------------------------------

begin certs
cat >"$work/openssl-p11.cnf" <<CONF
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
identity = pkcs11prov
module = $PKCS11_PROVIDER
pkcs11_module = $SOFTHSM2_MODULE
pin = $pin
activate = 1
CONF
cat >"$work/ca-ext.cnf" <<'CONF'
[root]
basicConstraints = critical, CA:TRUE, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[intermediate]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
CONF
# Informational: the step CLI route to the same certificate, which needs step-kms-plugin.
kms_uri="pkcs11:module-path=$SOFTHSM2_MODULE;token=$label?pin-value=$pin"
if step certificate create --profile root-ca --kms "$kms_uri" --key "pkcs11:id=01;object=root-ca" \
  "stepca-demo probe" "$work/step-probe.crt" >"$work/step-probe.txt" 2>&1 </dev/null; then
  step_probe="succeeded (step-kms-plugin present)"
else
  step_probe=$(grep -v '^$' "$work/step-probe.txt" | tail -n 1)
fi
root_key="pkcs11:token=$label;object=root-ca;type=private"
int_key="pkcs11:token=$label;object=intermediate-ca;type=private"
ossl_p11 req -new -x509 -key "$root_key" -subj "/CN=stepca-demo Root CA" -days 3650 -sha256 \
  -config "$work/ca-ext.cnf" -extensions root -set_serial "0x$("$OPENSSL_BIN" rand -hex 16)" \
  -out "$work/root.crt"
ossl_p11 req -new -key "$int_key" -subj "/CN=stepca-demo Intermediate CA" -config "$work/ca-ext.cnf" \
  -out "$work/intermediate.csr"
ossl_p11 x509 -req -in "$work/intermediate.csr" -CA "$work/root.crt" -CAkey "$root_key" -days 1825 \
  -sha256 -extfile "$work/ca-ext.cnf" -extensions intermediate \
  -set_serial "0x$("$OPENSSL_BIN" rand -hex 16)" -out "$work/intermediate.crt"
"$OPENSSL_BIN" verify -CAfile "$work/root.crt" "$work/intermediate.crt" >"$work/certs-verify.txt"
# The public key in each certificate must be the public half of the token key pair.
for pair in 01:root 02:intermediate; do
  id=${pair%%:*}
  name=${pair#*:}
  p11 --read-object --type pubkey --id "$id" -o "$work/token-pub-$id.der" >>"$work/logs/certs.log" 2>&1
  token_fp=$("$OPENSSL_BIN" pkey -pubin -inform DER -in "$work/token-pub-$id.der" -outform DER | shasum -a 256 | cut -d' ' -f1)
  cert_fp=$("$OPENSSL_BIN" x509 -in "$work/$name.crt" -noout -pubkey | pubkey_der_sha256)
  [ "$token_fp" = "$cert_fp" ]
  echo "$name.crt public key = token object id=$id (sha256 ${cert_fp:0:16}...)" >>"$work/certs-match.txt"
done
cat "$work/root.crt" "$work/intermediate.crt" >"$work/chain.pem"
pass "root and intermediate certificates signed with the token keys"
{
  "$OPENSSL_BIN" x509 -in "$work/root.crt" -noout -subject -issuer
  "$OPENSSL_BIN" x509 -in "$work/intermediate.crt" -noout -subject -issuer
  sed "s|$work/||" "$work/certs-verify.txt"
  cat "$work/certs-match.txt"
  echo "INFO step certificate create --kms: $step_probe"
} | show

# ---- 4. ca -------------------------------------------------------------------------------------

begin ca
mkdir -p "$STEPPATH/config" "$STEPPATH/db"
step crypto jwk create "$work/jwk.pub.json" "$work/jwk.priv.json" \
  --password-file "$work/provisioner.pw" >>"$work/logs/ca.log" 2>&1
encrypted_key=$(jq -r '[.protected, .encrypted_key, .iv, .ciphertext, .tag] | join(".")' "$work/jwk.priv.json")

port=""
for _ in $(seq 1 20); do
  candidate=$((20000 + RANDOM % 20000))
  if ! nc -z 127.0.0.1 "$candidate" >/dev/null 2>&1; then
    port=$candidate
    break
  fi
done
[ -n "$port" ]
ca_url="https://127.0.0.1:$port"

jq -n \
  --arg root "$work/root.crt" \
  --arg crt "$work/intermediate.crt" \
  --arg kms_uri "$kms_uri" \
  --arg address "127.0.0.1:$port" \
  --arg db "$STEPPATH/db" \
  --arg idp "$ca_url/1.0/crl" \
  --argjson jwk "$(cat "$work/jwk.pub.json")" \
  --arg enc "$encrypted_key" \
  '{
    root: $root,
    crt: $crt,
    key: "pkcs11:id=02;object=intermediate-ca",
    kms: {type: "pkcs11", uri: $kms_uri},
    address: $address,
    dnsNames: ["127.0.0.1"],
    db: {type: "badgerv2", dataSource: $db},
    crl: {enabled: true, generateOnRevoke: true, idpURL: $idp},
    authority: {provisioners: [{type: "JWK", name: "demo-admin", key: $jwk, encryptedKey: $enc}]},
    tls: {minVersion: 1.2, maxVersion: 1.3}
  }' >"$STEPPATH/config/ca.json"

step-ca "$STEPPATH/config/ca.json" >"$work/logs/step-ca.log" 2>&1 &
ca_pid=$!
healthy=0
for _ in $(seq 1 40); do
  kill -0 "$ca_pid" 2>/dev/null || break
  if step ca health --ca-url "$ca_url" --root "$work/root.crt" >>"$work/logs/ca.log" 2>&1; then
    healthy=1
    break
  fi
  sleep 0.25
done
if [ "$healthy" -ne 1 ]; then
  cat "$work/logs/step-ca.log" >>"$work/logs/ca.log"
  false
fi
# No PEM private key anywhere in the work directory: the CA keys exist only in the token.
pem_keys=$({ grep -rl -- '-----BEGIN .*PRIVATE KEY-----' "$work" 2>/dev/null || true; } | wc -l | tr -d ' ')
[ "$pem_keys" -eq 0 ]
pass "step-ca running at $ca_url, signing with the token key (health: ok)"
{
  jq -c '{key, kms: {type: .kms.type}}' "$STEPPATH/config/ca.json"
  grep -E 'Starting Smallstep CA|Serving HTTPS' "$work/logs/step-ca.log" | sed 's/^[0-9/]* [0-9:]* //'
  echo "files under the work directory containing a PEM private key: $pem_keys"
} | show

# ---- 5. leaf -----------------------------------------------------------------------------------

begin leaf
step ca certificate --provisioner demo-admin --provisioner-password-file "$work/provisioner.pw" \
  --ca-url "$ca_url" --root "$work/root.crt" \
  leaf.demo.test "$work/leaf.crt" "$work/leaf.key" >>"$work/logs/leaf.log" 2>&1
(cd "$work" && "$OPENSSL_BIN" verify -CAfile root.crt -untrusted intermediate.crt leaf.crt) >"$work/leaf-verify.txt"
pass "leaf certificate issued by step-ca; chain verifies"
{
  "$OPENSSL_BIN" x509 -in "$work/leaf.crt" -noout -subject -issuer -serial -startdate -enddate
  if "$OPENSSL_BIN" x509 -in "$work/leaf.crt" -noout -text | grep -q 'CRL Distribution Points'; then
    echo "leaf carries a CRL distribution point"
  else
    echo "leaf carries no CRL distribution point extension"
  fi
  cat "$work/leaf-verify.txt"
} | show

# ---- 6. revoke ---------------------------------------------------------------------------------

begin revoke
serial_dec=$(step certificate inspect --format json "$work/leaf.crt" | jq -r .serial_number)
serial_hex=$("$OPENSSL_BIN" x509 -in "$work/leaf.crt" -noout -serial | cut -d= -f2)
token=$(step ca token --revoke --provisioner demo-admin \
  --provisioner-password-file "$work/provisioner.pw" --ca-url "$ca_url" --root "$work/root.crt" \
  "$serial_dec" 2>>"$work/logs/revoke.log")
step ca revoke --token "$token" --ca-url "$ca_url" --root "$work/root.crt" \
  --reason "test-only demo revocation" "$serial_dec" >"$work/revoke-out.txt" 2>&1
cat "$work/revoke-out.txt" >>"$work/logs/revoke.log"
curl -sS --fail --cacert "$work/root.crt" -o "$work/crl.der" \
  -w 'GET /1.0/crl -> HTTP %{http_code}, %{content_type}\n' "$ca_url/1.0/crl" >"$work/crl-fetch.txt"
"$OPENSSL_BIN" crl -inform DER -in "$work/crl.der" -noout -text >"$work/crl.txt"
grep -q "Serial Number: $serial_hex\$" "$work/crl.txt"
"$OPENSSL_BIN" crl -inform DER -in "$work/crl.der" -CAfile "$work/chain.pem" -noout >"$work/crl-verify.txt" 2>&1
grep -q 'verify OK' "$work/crl-verify.txt"
# Renewal of the revoked certificate must be refused.
if step ca renew --force --ca-url "$ca_url" --root "$work/root.crt" \
  "$work/leaf.crt" "$work/leaf.key" >"$work/renew-out.txt" 2>&1; then
  echo "renewal of a revoked certificate was accepted" >>"$work/logs/revoke.log"
  false
fi
# Informational: OpenSSL's own CRL check of the leaf against this CRL.
"$OPENSSL_BIN" crl -inform DER -in "$work/crl.der" -out "$work/crl.pem"
crl_check=$( (cd "$work" && "$OPENSSL_BIN" verify -crl_check -CRLfile crl.pem -CAfile root.crt \
  -untrusted intermediate.crt leaf.crt 2>&1) || true)
pass "leaf serial $serial_hex listed in the CRL served by step-ca"
{
  grep -v '^$' "$work/revoke-out.txt" | tail -n 1
  cat "$work/crl-fetch.txt"
  grep -E 'Issuer:|Last Update|Next Update|URI:|Serial Number|Revocation Date' "$work/crl.txt" | sed 's/^ *//'
  echo "CRL signature: $(cat "$work/crl-verify.txt")"
  echo "step ca renew of the revoked leaf: $(grep -v '^$' "$work/renew-out.txt" | head -n 1)"
  echo "INFO openssl verify -crl_check: $(printf '%s\n' "$crl_check" | grep -E 'error|OK' | head -n 1)"
} | show

# ---- 7. attrs ----------------------------------------------------------------------------------

begin attrs
p11 --list-objects --type privkey >"$work/privkeys.txt" 2>>"$work/logs/attrs.log"
for name in root-ca intermediate-ca; do
  access=$(grep -A4 "label:[[:space:]]*$name\$" "$work/privkeys.txt" | grep 'Access:')
  case "$access" in
    *"sensitive, always sensitive, never extractable, local"*) ;;
    *)
      echo "$name: unexpected attributes: $access" >>"$work/logs/attrs.log"
      false
      ;;
  esac
done
pass "CA private keys are token objects: sensitive, never extractable, generated on the token"
grep -E 'label:|Usage:|Access:' "$work/privkeys.txt" | sed 's/^ *//' | show

# ---- 8. stop -----------------------------------------------------------------------------------

begin stop
stop_ca
if curl -s --max-time 2 --cacert "$work/root.crt" "$ca_url/health" >/dev/null 2>&1; then false; fi
pass "step-ca stopped; $ca_url no longer answers"

current=""
printf 'RESULT: %d PASS, 0 FAIL, 0 NOT RUN\n' "$passed"
