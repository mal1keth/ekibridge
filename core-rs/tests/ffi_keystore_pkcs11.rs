//! The PKCS#11 key store through the C ABI.
//!
//! Needs a token: `source scripts/softhsm-init.sh` exports `EKI_PKCS11_MODULE`,
//! `EKI_PKCS11_TOKEN_LABEL` and `EKI_PKCS11_PIN`. When any of them is unset each test prints a
//! note and returns. Tests are serialised through one static lock (C_Initialize and the login
//! state are per process) and every store is closed before its test returns, including on
//! failure, so SoftHSM2 never sees open sessions at exit. Keys a test creates are destroyed by
//! the `Store` guard, so the token is left as it was found.
//!
//! Rows: `ks_open` (PKCS#11) and every store row of docs/ffi-contract.md ("Per-function
//! contract"), and its "PKCS#11 object mapping and lifecycle".
//!
//! The open-failure tests run with no handle open: while any handle of this process is logged
//! in, `C_Login` answers `CKR_USER_ALREADY_LOGGED_IN`, which counts as success, so a wrong PIN
//! would go unnoticed.

mod common;

#[cfg(feature = "pkcs11")]
mod with_pkcs11 {
    use std::ffi::{CString, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::sync::Mutex;

    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::error::{Error as CkError, RvError};
    use cryptoki::object::{Attribute, CertificateType, KeyType, ObjectClass};
    use cryptoki::session::Session;

    use super::common::ks;
    use super::common::{
        In, Store, assert_info, assert_info_zero, assert_open_fails, config, label, label_of_len,
        last_error, prefilled_info, try_open,
    };
    use ekicore_abi::eki_status::{
        EKI_ERR_AUTH_FAILED, EKI_ERR_BACKEND, EKI_ERR_INVALID_ARGUMENT, EKI_ERR_KEY_EXISTS,
        EKI_ERR_KEY_NOT_FOUND, EKI_ERR_NULL_POINTER, EKI_ERR_WRONG_KEY_TYPE, EKI_OK,
    };
    use ekicore_abi::{
        EKI_KEY_AES_256, EKI_KEY_ECDSA_P256, EKI_KEY_HMAC_SHA256, EKI_KS_PKCS11, eki_key_id,
        eki_ks_config,
    };

    /// Token parameters from the environment.
    struct Token {
        module: CString,
        label: CString,
        pin: CString,
    }

    impl Token {
        fn config(&self) -> eki_ks_config {
            config(
                EKI_KS_PKCS11,
                Some(&self.module),
                Some(&self.label),
                Some(&self.pin),
            )
        }
    }

    fn env(name: &str) -> Option<CString> {
        let value = std::env::var(name).ok().filter(|v| !v.is_empty())?;
        Some(CString::new(value).expect("environment value has no NUL"))
    }

    fn token() -> Option<Token> {
        Some(Token {
            module: env("EKI_PKCS11_MODULE")?,
            label: env("EKI_PKCS11_TOKEN_LABEL")?,
            pin: env("EKI_PKCS11_PIN")?,
        })
    }

    /// Serialises every test that touches the token.
    static TOKEN_LOCK: Mutex<()> = Mutex::new(());

    /// Runs `f` with the token parameters while holding the lock, or skips.
    fn with_token(f: impl FnOnce(&Token)) {
        // A failed test poisons the lock; the token itself is still usable.
        let _guard = TOKEN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(token) = token() else {
            eprintln!(
                "skipped: set EKI_PKCS11_MODULE, EKI_PKCS11_TOKEN_LABEL and EKI_PKCS11_PIN \
                 (source scripts/softhsm-init.sh)"
            );
            return;
        };
        f(&token);
    }

    /// Runs `f` on a freshly opened store of the test token.
    fn with_store(f: impl FnOnce(&Store)) {
        with_token(|token| f(&Store::open(&token.config())));
    }

    // --- open ---------------------------------------------------------------------------------

    #[test]
    fn open_and_close() {
        with_store(|store| {
            let id = store.generate(EKI_KEY_HMAC_SHA256, "eki-test");
            assert_info(&store.info(&id), EKI_KEY_HMAC_SHA256, "eki-test");
        });
    }

    #[test]
    fn open_wrong_pin_is_backend() {
        with_token(|token| {
            for pin in ["0000", "12345", &"9".repeat(255)] {
                let pin = label(pin);
                let cfg = config(
                    EKI_KS_PKCS11,
                    Some(&token.module),
                    Some(&token.label),
                    Some(&pin),
                );
                assert_open_fails(&cfg, EKI_ERR_BACKEND);
            }
        });
    }

    #[test]
    fn open_unknown_token_label_is_backend() {
        with_token(|token| {
            for text in ["no-such-token", &"z".repeat(32)] {
                let other = label(text);
                let cfg = config(
                    EKI_KS_PKCS11,
                    Some(&token.module),
                    Some(&other),
                    Some(&token.pin),
                );
                assert_open_fails(&cfg, EKI_ERR_BACKEND);
            }
        });
    }

    #[test]
    fn open_missing_module_is_backend() {
        with_token(|token| {
            let module = label("/nonexistent/libnot-a-pkcs11-module.so");
            let cfg = config(
                EKI_KS_PKCS11,
                Some(&module),
                Some(&token.label),
                Some(&token.pin),
            );
            assert_open_fails(&cfg, EKI_ERR_BACKEND);
        });
    }

    #[test]
    fn open_null_config_fields_in_field_order() {
        with_token(|token| {
            let (m, l, p) = (Some(&token.module), Some(&token.label), Some(&token.pin));
            for (name, module, token_label, pin) in [
                ("module_path", None, l, p),
                ("token_label", m, None, p),
                ("user_pin", m, l, None),
                ("all", None, None, None),
            ] {
                let opened = try_open(&config(EKI_KS_PKCS11, module, token_label, pin));
                assert_eq!(opened.status, EKI_ERR_NULL_POINTER, "{name} NULL");
                assert!(opened.out_is_null);
            }
        });
    }

    #[test]
    fn open_null_field_before_format_of_another_field() {
        // `ks_open` makes the NULL checks of all three fields before the format checks
        // ("Validation order"): a malformed token label together with a NULL PIN is NULL_POINTER.
        with_token(|token| {
            let empty = label("");
            let cfg = config(EKI_KS_PKCS11, Some(&token.module), Some(&empty), None);
            assert_open_fails(&cfg, EKI_ERR_NULL_POINTER);
        });
    }

    #[test]
    fn open_token_label_format_is_invalid() {
        with_token(|token| {
            let long = label_of_len(33);
            let empty = label("");
            let ctrl = label("eki\x01bridge");
            let high = CString::new(b"eki\x80".to_vec()).unwrap();
            for (name, bad) in [
                ("33 bytes", &long),
                ("empty", &empty),
                ("0x01", &ctrl),
                ("0x80", &high),
            ] {
                let cfg = config(
                    EKI_KS_PKCS11,
                    Some(&token.module),
                    Some(bad),
                    Some(&token.pin),
                );
                let opened = try_open(&cfg);
                assert_eq!(
                    opened.status, EKI_ERR_INVALID_ARGUMENT,
                    "token label {name}"
                );
                assert!(opened.out_is_null);
            }
        });
    }

    #[test]
    fn open_pin_length_is_invalid() {
        with_token(|token| {
            let empty = label("");
            let long = label(&"1".repeat(256));
            for (name, pin) in [("empty", &empty), ("256 bytes", &long)] {
                let cfg = config(
                    EKI_KS_PKCS11,
                    Some(&token.module),
                    Some(&token.label),
                    Some(pin),
                );
                let opened = try_open(&cfg);
                assert_eq!(opened.status, EKI_ERR_INVALID_ARGUMENT, "pin {name}");
                assert!(opened.out_is_null);
            }
        });
    }

    // --- shared scenarios ---------------------------------------------------------------------

    #[test]
    fn lifecycle() {
        with_store(ks::lifecycle);
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        with_store(ks::wrap_unwrap_round_trip);
    }

    #[test]
    fn generate_rows() {
        with_store(ks::generate_rows);
    }

    #[test]
    fn generate_null_rows() {
        with_store(ks::generate_null_rows);
    }

    #[test]
    fn lookup_rows() {
        with_store(ks::lookup_rows);
    }

    #[test]
    fn lookup_null_rows() {
        with_store(ks::lookup_null_rows);
    }

    #[test]
    fn wrap_rows() {
        with_store(ks::wrap_rows);
    }

    #[test]
    fn unwrap_rows() {
        with_store(ks::unwrap_rows);
    }

    #[test]
    fn last_error_rows() {
        with_store(ks::last_error_rows);
    }

    // --- PKCS#11-specific ---------------------------------------------------------------------

    #[test]
    fn empty_message_hmac_and_sign_are_ok() {
        // SoftHSM2 rejects a NULL data pointer even with length 0; the library must
        // substitute a dummy pointer, so both NULL and non-NULL empty messages work.
        with_store(|store| {
            let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
            let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa");
            let pk = store.public_key(&ec);
            for msg in [In::Null(0), In::Bytes(&[])] {
                let mut out = [0xA5; 32];
                assert_eq!(
                    ks::hmac(store.ptr(), Some(&mac), msg, Some(&mut out)),
                    EKI_OK,
                    "{msg:?}"
                );
                let mut sig = [0xA5; 64];
                assert_eq!(
                    ks::sign(store.ptr(), Some(&ec), msg, Some(&mut sig)),
                    EKI_OK,
                    "{msg:?}"
                );
                assert_eq!(ks::verify(&pk, In::Null(0), &sig), EKI_OK);
            }
        });
    }

    #[test]
    fn keys_persist_in_the_token_across_handles() {
        with_token(|token| {
            let id = {
                let store = Store::open(&token.config());
                let id = store.generate(EKI_KEY_HMAC_SHA256, "eki-test persistent");
                store.forget(&id);
                id
            };
            let store = Store::open(&token.config());
            store.track(id);
            assert_info(&store.info(&id), EKI_KEY_HMAC_SHA256, "eki-test persistent");
            store.destroy(&id);
        });
    }

    #[test]
    fn second_handle_survives_closing_the_first() {
        // Close never logs out and finalizes only at zero open handles.
        with_token(|token| {
            let b = Store::open(&token.config());
            let mac = {
                let a = Store::open(&token.config());
                let mac = a.generate(EKI_KEY_HMAC_SHA256, "eki-test shared");
                a.forget(&mac);
                b.track(mac);
                assert_eq!(a.hmac(&mac, b"m"), b.hmac(&mac, b"m"));
                mac
            };
            let _ = b.hmac(&mac, b"m");
            let ec = b.generate(EKI_KEY_ECDSA_P256, "eki-test after close");
            let sig = b.sign(&ec, In::Bytes(b"m"));
            assert_eq!(
                ks::verify(&b.public_key(&ec), In::Bytes(b"m"), &sig),
                EKI_OK
            );
        });
    }

    #[test]
    fn destroy_removes_both_halves_of_a_key_pair() {
        with_store(|store| {
            let kek = store.generate(EKI_KEY_AES_256, "eki-test kek");
            let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
            let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa");
            store.destroy(&ec);
            let mut pk = [0xA5; 65];
            assert_eq!(
                ks::get_public_key(store.ptr(), Some(&ec), Some(&mut pk)),
                EKI_ERR_KEY_NOT_FOUND
            );
            // If the public half were left behind, the id would still be taken.
            let blob = store.wrap(&kek, &mac);
            store.unwrap(&kek, &blob, EKI_KEY_HMAC_SHA256, "eki-test reused id", &ec);
            assert_info(&store.info(&ec), EKI_KEY_HMAC_SHA256, "eki-test reused id");
        });
    }

    // --- Module and session lifetime ----------------------------------------------------------

    #[test]
    fn two_open_handles_see_each_others_changes() {
        // Both handles share one module context and look keys up again on every call, so a key
        // created or destroyed through one is seen at once through the other.
        with_token(|token| {
            let a = Store::open(&token.config());
            let b = Store::open(&token.config());
            let ec = a.generate(EKI_KEY_ECDSA_P256, "eki-test shared");
            assert_info(&b.info(&ec), EKI_KEY_ECDSA_P256, "eki-test shared");
            let sig = b.sign(&ec, In::Bytes(b"m"));
            assert_eq!(
                ks::verify(&a.public_key(&ec), In::Bytes(b"m"), &sig),
                EKI_OK
            );
            a.forget(&ec);
            b.destroy(&ec);
            let mut info = prefilled_info();
            let status = ks::get_info(a.ptr(), Some(&ec), Some(&mut info));
            assert_eq!(status, EKI_ERR_KEY_NOT_FOUND);
            assert_info_zero(&info);
            // Both handles stay usable.
            let mac = b.generate(EKI_KEY_HMAC_SHA256, "eki-test after destroy");
            assert_eq!(a.hmac(&mac, b"m"), b.hmac(&mac, b"m"));
        });
    }

    #[test]
    fn open_succeeds_after_failed_opens() {
        // A failed open releases what it acquired (session, module reference), so the module is
        // finalised again and the next open initialises it and logs in afresh.
        with_token(|token| {
            let wrong_pin = label("0000");
            let other_label = label("no-such-token");
            let missing = label("/nonexistent/libnot-a-pkcs11-module.so");
            let (m, l, p) = (Some(&token.module), Some(&token.label), Some(&token.pin));
            for (module, token_label, pin) in [
                (m, l, Some(&wrong_pin)),
                (m, Some(&other_label), p),
                (Some(&missing), l, p),
                (m, l, Some(&wrong_pin)),
            ] {
                let cfg = config(EKI_KS_PKCS11, module, token_label, pin);
                assert_open_fails(&cfg, EKI_ERR_BACKEND);
            }
            let store = Store::open(&token.config());
            let id = store.generate(EKI_KEY_HMAC_SHA256, "eki-test after failures");
            assert_info(
                &store.info(&id),
                EKI_KEY_HMAC_SHA256,
                "eki-test after failures",
            );
        });
    }

    #[test]
    fn open_with_wrong_pin_while_logged_in_succeeds() {
        // The login state belongs to the process; while a handle is logged in, C_Login
        // answers CKR_USER_ALREADY_LOGGED_IN whatever the PIN, which counts as success.
        with_token(|token| {
            let _logged_in = Store::open(&token.config());
            let wrong_pin = label("0000-not-the-pin");
            let cfg = config(
                EKI_KS_PKCS11,
                Some(&token.module),
                Some(&token.label),
                Some(&wrong_pin),
            );
            let second = Store::open(&cfg);
            let id = second.generate(EKI_KEY_AES_256, "eki-test second login");
            assert_info(&second.info(&id), EKI_KEY_AES_256, "eki-test second login");
        });
    }

    /// A shared library that exports no `C_GetFunctionList`, if one is known on this system.
    fn library_without_pkcs11() -> Option<&'static str> {
        if cfg!(target_os = "macos") {
            // In the dyld shared cache rather than on disk, but `dlopen` finds it.
            return Some("/usr/lib/libSystem.B.dylib");
        }
        [
            "/lib/x86_64-linux-gnu/libm.so.6",
            "/lib/aarch64-linux-gnu/libm.so.6",
            "/usr/lib64/libm.so.6",
            "/usr/lib/libm.so.6",
        ]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
    }

    #[test]
    fn open_non_module_is_backend() {
        with_token(|token| {
            let mut paths = vec!["", "/dev/null"];
            paths.extend(library_without_pkcs11());
            for path in paths {
                let module = label(path);
                let cfg = config(
                    EKI_KS_PKCS11,
                    Some(&module),
                    Some(&token.label),
                    Some(&token.pin),
                );
                let opened = try_open(&cfg);
                assert_eq!(opened.status, EKI_ERR_BACKEND, "module path {path:?}");
                assert!(opened.out_is_null);
            }
        });
    }

    // --- Objects the library did not create ("Foreign objects") -------------------------------

    /// A cryptoki session of its own on the test token, for objects the library did not create.
    /// It is opened while `store` is open, so the module is already initialised (this context
    /// gets CKR_CRYPTOKI_ALREADY_INITIALIZED and never finalises) and the store's login covers
    /// this session. The borrow of the store makes the session close before the store does.
    struct RawToken<'s> {
        session: Session,
        _context: Pkcs11,
        _store: &'s Store,
    }

    impl<'s> RawToken<'s> {
        fn open(token: &Token, store: &'s Store) -> RawToken<'s> {
            let path = OsStr::from_bytes(token.module.as_bytes());
            let context = Pkcs11::new(path).expect("the test module loads");
            match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
                Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
                other => {
                    if other.is_ok() {
                        let _ = context.clone().finalize();
                    }
                    panic!("the open store should have initialised the module: {other:?}");
                }
            }
            let wanted = token.label.to_str().expect("ASCII token label");
            let slot = context
                .get_slots_with_token()
                .expect("C_GetSlotList")
                .into_iter()
                .find(|&slot| {
                    context
                        .get_token_info(slot)
                        .is_ok_and(|info| info.label() == wanted)
                })
                .expect("the test token is present");
            let session = context.open_rw_session(slot).expect("C_OpenSession");
            RawToken {
                session,
                _context: context,
                _store: store,
            }
        }

        fn create(&self, template: &[Attribute]) {
            self.session
                .create_object(template)
                .expect("C_CreateObject");
        }

        /// Destroys the objects of `class` that carry `id`.
        fn destroy(&self, id: &eki_key_id, class: ObjectClass) {
            let search = [Attribute::Class(class), Attribute::Id(id.bytes.to_vec())];
            let found = self.session.find_objects(&search).expect("C_FindObjects");
            assert!(!found.is_empty(), "no object of {class:?} carries the id");
            for object in found {
                self.session
                    .destroy_object(object)
                    .expect("C_DestroyObject");
            }
        }
    }

    /// A random id, so that objects a failed run left behind cannot collide with this run's.
    fn random_id() -> eki_key_id {
        let mut id = eki_key_id { bytes: [0; 16] };
        getrandom::fill(&mut id.bytes).expect("getrandom");
        id
    }

    /// A token secret key of `key_type` with the value `value`, labelled `text`, carrying the
    /// usage attributes of its row in the state table.
    fn secret_key(id: &eki_key_id, key_type: KeyType, text: &[u8], value: &[u8]) -> Vec<Attribute> {
        let mut template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(key_type),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Id(id.bytes.to_vec()),
            Attribute::Label(text.to_vec()),
            Attribute::Value(value.to_vec()),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
        ];
        if key_type == KeyType::AES {
            template.extend([
                Attribute::Wrap(true),
                Attribute::Unwrap(true),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
            ]);
        } else {
            template.extend([Attribute::Sign(true), Attribute::Verify(true)]);
        }
        template
    }

    /// Asserts that an operation that needs the key's algorithm or label fails as a backend
    /// failure with a message.
    #[track_caller]
    fn assert_backend_failure(store: &Store, status: ekicore_abi::eki_status, what: &str) {
        assert_eq!(status, EKI_ERR_BACKEND, "{what}");
        assert!(!last_error(store.ptr()).is_empty(), "{what}: message");
    }

    #[test]
    fn foreign_object_takes_the_id_and_can_be_destroyed() {
        with_token_store(|token, store| {
            let id = random_id();
            {
                let raw = RawToken::open(token, store);
                // CKO_DATA would not do: data objects have no CKA_ID.
                raw.create(&[
                    Attribute::Class(ObjectClass::CERTIFICATE),
                    Attribute::CertificateType(CertificateType::X_509),
                    Attribute::Token(true),
                    Attribute::Id(id.bytes.to_vec()),
                    Attribute::Label(b"eki-test certificate".to_vec()),
                    Attribute::Subject(b"not a DER name".to_vec()),
                    Attribute::Value(b"not a DER certificate".to_vec()),
                ]);
            }
            store.track(id);
            let mut info = prefilled_info();
            let status = ks::get_info(store.ptr(), Some(&id), Some(&mut info));
            assert_backend_failure(store, status, "get_info");
            assert_info_zero(&info);
            let mut out = [0xA5; 32];
            let status = ks::hmac(store.ptr(), Some(&id), In::Bytes(b"m"), Some(&mut out));
            assert_backend_failure(store, status, "ks_hmac");
            // It takes the id: unwrapping into it is KEY_EXISTS.
            let kek = store.generate(EKI_KEY_AES_256, "eki-test kek");
            let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
            let blob = store.wrap(&kek, &mac);
            let text = label("eki-test copy");
            let status = ks::unwrap(
                store.ptr(),
                Some(&kek),
                In::Bytes(&blob),
                EKI_KEY_HMAC_SHA256,
                text.as_ptr(),
                Some(&id),
            );
            assert_eq!(status, EKI_ERR_KEY_EXISTS);
            // It can be destroyed, once.
            store.destroy(&id);
            let status = ks::get_info(store.ptr(), Some(&id), Some(&mut prefilled_info()));
            assert_eq!(status, EKI_ERR_KEY_NOT_FOUND);
            assert_eq!(ks::destroy(store.ptr(), Some(&id)), EKI_ERR_KEY_NOT_FOUND);
        });
    }

    #[test]
    fn wrap_checks_existence_before_describing_a_foreign_kek() {
        // `ks_wrap` ("Per-function contract"): kek exists → key exists → kek is AES_256. A foreign
        // kek is a backend failure only once both ids are known to exist.
        with_token_store(|token, store| {
            let foreign = random_id();
            {
                let raw = RawToken::open(token, store);
                raw.create(&secret_key(&foreign, KeyType::AES, b"", &[0x33; 32]));
            }
            store.track(foreign);
            let mut out = [0xA5; 40];
            let missing = random_id();
            let status = ks::wrap(store.ptr(), Some(&foreign), Some(&missing), Some(&mut out));
            assert_eq!(status, EKI_ERR_KEY_NOT_FOUND);
            assert_eq!(out, [0; 40]);
            let kek = store.generate(EKI_KEY_AES_256, "eki-test kek");
            let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
            let status = ks::wrap(store.ptr(), Some(&foreign), Some(&mac), Some(&mut out));
            assert_backend_failure(store, status, "ks_wrap under a foreign kek");
            // A foreign key is described only after the type check of the kek.
            let status = ks::wrap(store.ptr(), Some(&kek), Some(&foreign), Some(&mut out));
            assert_backend_failure(store, status, "ks_wrap of a foreign key");
            let status = ks::wrap(store.ptr(), Some(&mac), Some(&foreign), Some(&mut out));
            assert_eq!(status, EKI_ERR_WRONG_KEY_TYPE);
        });
    }

    #[test]
    fn failed_unwrap_names_the_return_code() {
        // The token reports a failed integrity check with a code other causes share, so the
        // AUTH_FAILED of unwrap carries the code as its message, as in the C++ library.
        with_token_store(|_, store| {
            let kek = store.generate(EKI_KEY_AES_256, "eki-test kek");
            let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
            let mut blob = store.wrap(&kek, &mac);
            blob[20] ^= 0x01;
            let id = random_id();
            let text = label("eki-test copy");
            let status = ks::unwrap(
                store.ptr(),
                Some(&kek),
                In::Bytes(&blob),
                EKI_KEY_HMAC_SHA256,
                text.as_ptr(),
                Some(&id),
            );
            assert_eq!(status, EKI_ERR_AUTH_FAILED);
            let message = last_error(store.ptr());
            assert!(message.starts_with("C_UnwrapKey failed: CKR_"), "{message}");
        });
    }

    #[test]
    fn secret_key_with_an_invalid_label_is_foreign() {
        with_token_store(|token, store| {
            let long = [b'L'; 65];
            for text in [&b""[..], &long, b"eki\x01test", b"eki\x80test"] {
                let id = random_id();
                {
                    let raw = RawToken::open(token, store);
                    raw.create(&secret_key(&id, KeyType::GENERIC_SECRET, text, &[0x44; 32]));
                }
                store.track(id);
                let mut info = prefilled_info();
                let status = ks::get_info(store.ptr(), Some(&id), Some(&mut info));
                assert_backend_failure(store, status, "get_info");
                let mut out = [0xA5; 32];
                let status = ks::hmac(store.ptr(), Some(&id), In::Bytes(b"m"), Some(&mut out));
                assert_backend_failure(store, status, "ks_hmac");
                store.destroy(&id);
            }
        });
    }

    #[test]
    fn key_pair_without_its_public_half_is_foreign() {
        with_token_store(|token, store| {
            let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test half");
            RawToken::open(token, store).destroy(&ec, ObjectClass::PUBLIC_KEY);
            let mut info = prefilled_info();
            let status = ks::get_info(store.ptr(), Some(&ec), Some(&mut info));
            assert_backend_failure(store, status, "get_info");
            let mut sig = [0xA5; 64];
            let status = ks::sign(store.ptr(), Some(&ec), In::Bytes(b"m"), Some(&mut sig));
            assert_backend_failure(store, status, "ks_sign");
            let mut pk = [0xA5; 65];
            let status = ks::get_public_key(store.ptr(), Some(&ec), Some(&mut pk));
            assert_backend_failure(store, status, "get_public_key");
            // Destroy removes the private half that is left.
            store.destroy(&ec);
            let status = ks::get_info(store.ptr(), Some(&ec), Some(&mut prefilled_info()));
            assert_eq!(status, EKI_ERR_KEY_NOT_FOUND);
        });
    }

    #[test]
    fn secret_keys_created_elsewhere_are_usable() {
        // Keys of the shape of the mapping table made by another program: recognised with their
        // algorithm and
        // label, and the token's CKM_SHA256_HMAC and CKM_AES_KEY_WRAP agree with the library's
        // own HMAC and RFC 3394 code over the same key bytes.
        with_token_store(|token, store| {
            let (kek, mac) = (random_id(), random_id());
            let (kek_value, mac_value) = ([0x11; 32], [0x22; 32]);
            {
                let raw = RawToken::open(token, store);
                raw.create(&secret_key(
                    &kek,
                    KeyType::AES,
                    b"eki-test raw aes",
                    &kek_value,
                ));
                raw.create(&secret_key(
                    &mac,
                    KeyType::GENERIC_SECRET,
                    b"eki-test raw hmac",
                    &mac_value,
                ));
            }
            store.track(kek);
            store.track(mac);
            assert_info(&store.info(&kek), EKI_KEY_AES_256, "eki-test raw aes");
            assert_info(&store.info(&mac), EKI_KEY_HMAC_SHA256, "eki-test raw hmac");
            let expected = ekicore_rs::hmac::hmac_sha256(&mac_value, b"message").expect("HMAC");
            assert_eq!(store.hmac(&mac, b"message"), expected);
            assert_eq!(
                store.wrap(&kek, &mac),
                ekicore_rs::keywrap::wrap(&kek_value, &mac_value)
            );
            assert_eq!(
                store.wrap(&kek, &kek),
                ekicore_rs::keywrap::wrap(&kek_value, &kek_value)
            );
        });
    }

    /// Runs `f` with the token parameters and a freshly opened store of the test token.
    fn with_token_store(f: impl FnOnce(&Token, &Store)) {
        with_token(|token| f(token, &Store::open(&token.config())));
    }
}

/// Without the `pkcs11` feature the backend is a known selector that is not compiled in.
#[cfg(not(feature = "pkcs11"))]
mod without_pkcs11 {
    use super::common::{config, label, try_open};
    use ekicore_abi::{EKI_KS_PKCS11, eki_status};

    #[test]
    fn pkcs11_backend_not_compiled_in_is_unsupported() {
        let module = label("/nonexistent/module.so");
        let token_label = label("ekibridge");
        let pin = label("1234");
        let opened = try_open(&config(
            EKI_KS_PKCS11,
            Some(&module),
            Some(&token_label),
            Some(&pin),
        ));
        assert_eq!(opened.status, eki_status::EKI_ERR_UNSUPPORTED);
    }
}
