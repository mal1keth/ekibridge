//! Key lifecycle, dual control and the audit log on the PKCS#11 store, through the C ABI.
//!
//! Needs a token, as `ffi_keystore_pkcs11.rs` does: `EKI_PKCS11_MODULE`,
//! `EKI_PKCS11_TOKEN_LABEL` and `EKI_PKCS11_PIN`. When any of them is unset each test prints a
//! note and returns. Tests are serialised through one static lock and every store is closed
//! before its test returns.
//!
//! Rows: the shared scenarios of `common::lifecycle` (docs/ffi-contract.md: "Key states",
//! "Opening a store with ABI 2", "Dual control", "Per-function contract"), and what only a token
//! shows: the usage attributes that hold the state ("PKCS#11 object mapping and lifecycle"), the
//! token itself refusing what the state forbids (observable only below the ABI, through a
//! session of this test, because the library refuses first), a state seen through a second
//! handle, an attribute combination that is no state, and a key destroyed through another handle
//! while a destroy request for it waits.

mod common;

#[cfg(feature = "pkcs11")]
mod with_pkcs11 {
    use std::ffi::{CString, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::sync::Mutex;

    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::error::{Error as CkError, RvError};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
    use cryptoki::session::Session;

    use super::common::lifecycle::{self, Approvers, audit_verify};
    use super::common::{
        Store, assert_open_v2_fails, config, config_v2, fixed_id, label, last_error,
    };
    use ekicore_abi::eki_status::{
        EKI_ERR_BACKEND, EKI_ERR_INVALID_ARGUMENT, EKI_ERR_KEY_NOT_FOUND, EKI_ERR_NULL_POINTER,
        EKI_OK,
    };
    use ekicore_abi::{
        EKI_KEY_AES_256, EKI_KEY_ECDSA_P256, EKI_KEY_HMAC_SHA256, EKI_KEY_STATE_ACTIVE,
        EKI_KEY_STATE_RETIRED, EKI_KEY_STATE_REVOKED, EKI_KS_PKCS11, eki_key_id, eki_ks_config,
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

    /// Runs `f` with the token parameters and a freshly opened store of the test token.
    fn with_token_store(f: impl FnOnce(&Token, &Store)) {
        with_token(|token| f(token, &Store::open(&token.config())));
    }

    /// A store of the token with approvers 0, 1 and 2 of `approvers`.
    fn dual_store(token: &Token, approvers: &Approvers) -> Store {
        let keys = approvers.bytes(3);
        Store::open_v2(&config_v2(&token.config(), None, Some(&keys), 3))
    }

    // --- The shared scenarios ------------------------------------------------------------------

    #[test]
    fn state_table_rows() {
        with_token_store(|_, store| lifecycle::state_table_rows(store));
    }

    #[test]
    fn rotate_rows() {
        with_token_store(|_, store| lifecycle::rotate_rows(store));
    }

    #[test]
    fn revoke_rows() {
        with_token_store(|_, store| lifecycle::revoke_rows(store));
    }

    #[test]
    fn hmac_verify_rows() {
        with_token_store(|_, store| lifecycle::hmac_verify_rows(store));
    }

    #[test]
    fn get_info_v2_rows() {
        with_token_store(|_, store| lifecycle::get_info_v2_rows(store));
    }

    #[test]
    fn no_approver_rows() {
        with_token_store(|_, store| lifecycle::no_approver_rows(store));
    }

    #[test]
    fn dual_control_rows() {
        with_token(|token| {
            let approvers = Approvers::new(4);
            lifecycle::dual_control_rows(&dual_store(token, &approvers), &approvers);
        });
    }

    #[test]
    fn open_v2_rows() {
        with_token(|token| lifecycle::open_v2_rows(&token.config(), &Approvers::new(9)));
    }

    // --- The token underneath ------------------------------------------------------------------

    /// A cryptoki session of its own on the test token, opened while `store` is open, so the
    /// module is already initialised and the store's login covers this session. The borrow of
    /// the store makes the session close before the store does.
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

        /// The one object of `class` that carries `id`.
        fn object(&self, id: &eki_key_id, class: ObjectClass) -> ObjectHandle {
            let search = [Attribute::Class(class), Attribute::Id(id.bytes.to_vec())];
            let found = self.session.find_objects(&search).expect("C_FindObjects");
            assert_eq!(found.len(), 1, "one object of {class:?}");
            found[0]
        }

        /// The values of the usage flags `kinds` of `object`, in order.
        fn flags(&self, object: ObjectHandle, kinds: &[AttributeType]) -> Vec<bool> {
            let attributes = self
                .session
                .get_attributes(object, kinds)
                .expect("C_GetAttributeValue");
            kinds
                .iter()
                .map(|kind| {
                    match attributes
                        .iter()
                        .find(|a| a.attribute_type() == *kind)
                        .expect("the flag is readable")
                    {
                        Attribute::Wrap(v)
                        | Attribute::Encrypt(v)
                        | Attribute::Unwrap(v)
                        | Attribute::Decrypt(v)
                        | Attribute::Sign(v)
                        | Attribute::Verify(v) => *v,
                        other => panic!("not a usage flag: {other:?}"),
                    }
                })
                .collect()
        }

        /// The flags of the contract's table for a key of `alg`: protect group, check group.
        fn state_flags(
            &self,
            id: &eki_key_id,
            alg: ekicore_abi::eki_key_alg,
        ) -> (Vec<bool>, Vec<bool>) {
            use AttributeType::{Decrypt, Encrypt, Sign, Unwrap, Verify, Wrap};
            if alg == EKI_KEY_AES_256 {
                let key = self.object(id, ObjectClass::SECRET_KEY);
                (
                    self.flags(key, &[Wrap, Encrypt]),
                    self.flags(key, &[Unwrap, Decrypt]),
                )
            } else if alg == EKI_KEY_HMAC_SHA256 {
                let key = self.object(id, ObjectClass::SECRET_KEY);
                (self.flags(key, &[Sign]), self.flags(key, &[Verify]))
            } else {
                let private = self.object(id, ObjectClass::PRIVATE_KEY);
                let public = self.object(id, ObjectClass::PUBLIC_KEY);
                (self.flags(private, &[Sign]), self.flags(public, &[Verify]))
            }
        }

        /// Sets usage flags of `object` directly, as another program could.
        fn set(&self, object: ObjectHandle, attributes: &[Attribute]) {
            self.session
                .update_attributes(object, attributes)
                .expect("C_SetAttributeValue");
        }
    }

    #[track_caller]
    fn assert_refused<T: std::fmt::Debug>(result: Result<T, CkError>, what: &str) {
        match result {
            Err(CkError::Pkcs11(RvError::KeyFunctionNotPermitted, _)) => {}
            other => panic!("{what}: the token should refuse, got {other:?}"),
        }
    }

    #[test]
    fn usage_attributes_hold_the_state() {
        with_token_store(|token, store| {
            let raw = RawToken::open(token, store);
            for (alg, protect, check) in [
                (EKI_KEY_AES_256, 2, 2),
                (EKI_KEY_HMAC_SHA256, 1, 1),
                (EKI_KEY_ECDSA_P256, 1, 1),
            ] {
                let id = store.generate(alg, "eki-test state flags");
                let flags = |all_protect: bool, all_check: bool| {
                    (vec![all_protect; protect], vec![all_check; check])
                };
                assert_eq!(raw.state_flags(&id, alg), flags(true, true), "ACTIVE");
                store.rotate(&id);
                assert_eq!(raw.state_flags(&id, alg), flags(false, true), "RETIRED");
                store.revoke(&id);
                assert_eq!(raw.state_flags(&id, alg), flags(false, false), "REVOKED");
                // An ACTIVE key revoked directly passes through RETIRED to REVOKED.
                let direct = store.generate(alg, "eki-test direct revoke");
                store.revoke(&direct);
                assert_eq!(raw.state_flags(&direct, alg), flags(false, false));
            }
        });
    }

    #[test]
    fn the_token_refuses_what_the_state_forbids() {
        with_token_store(|token, store| {
            let raw = RawToken::open(token, store);
            let kek = store.generate(EKI_KEY_AES_256, "eki-test kek");
            let active_kek = store.generate(EKI_KEY_AES_256, "eki-test active kek");
            let mac = store.generate(EKI_KEY_HMAC_SHA256, "eki-test hmac");
            let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test ecdsa");
            let tag = store.hmac(&mac, b"m");
            let blob = store.wrap(&kek, &mac);
            for id in [kek, mac, ec] {
                store.rotate(&id);
            }
            let kek_object = raw.object(&kek, ObjectClass::SECRET_KEY);
            let active_object = raw.object(&active_kek, ObjectClass::SECRET_KEY);
            let mac_object = raw.object(&mac, ObjectClass::SECRET_KEY);
            let ec_private = raw.object(&ec, ObjectClass::PRIVATE_KEY);
            let s = &raw.session;
            assert_refused(
                s.sign(&Mechanism::Sha256Hmac, mac_object, b"m"),
                "RETIRED HMAC sign",
            );
            assert_refused(
                s.sign(&Mechanism::Ecdsa, ec_private, &[0; 32]),
                "RETIRED ECDSA sign",
            );
            assert_refused(
                s.wrap_key(&Mechanism::AesKeyWrap, kek_object, mac_object),
                "RETIRED kek wrap",
            );
            s.verify(&Mechanism::Sha256Hmac, mac_object, b"m", &tag)
                .expect("RETIRED HMAC verify");
            s.wrap_key(&Mechanism::AesKeyWrap, active_object, mac_object)
                .expect("a RETIRED key under an ACTIVE kek");
            for id in [kek, mac, ec] {
                store.revoke(&id);
            }
            assert_refused(
                s.verify(&Mechanism::Sha256Hmac, mac_object, b"m", &tag),
                "REVOKED HMAC verify",
            );
            let template = [
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(cryptoki::object::KeyType::GENERIC_SECRET),
                Attribute::Token(false),
            ];
            assert_refused(
                s.unwrap_key(&Mechanism::AesKeyWrap, kek_object, &blob, &template),
                "REVOKED kek unwrap",
            );
        });
    }

    #[test]
    fn a_state_change_is_seen_through_another_handle() {
        with_token(|token| {
            let a = Store::open(&token.config());
            let b = Store::open(&token.config());
            let id = a.generate(EKI_KEY_HMAC_SHA256, "eki-test shared");
            assert_eq!(b.state(&id), EKI_KEY_STATE_ACTIVE);
            let new = a.rotate(&id);
            assert_eq!(b.state(&id), EKI_KEY_STATE_RETIRED);
            assert_eq!(b.state(&new), EKI_KEY_STATE_ACTIVE);
            b.revoke(&id);
            assert_eq!(a.state(&id), EKI_KEY_STATE_REVOKED);
        });
    }

    #[test]
    fn an_attribute_combination_outside_the_table_is_foreign() {
        with_token_store(|token, store| {
            let raw = RawToken::open(token, store);
            let aes = store.generate(EKI_KEY_AES_256, "eki-test half retired");
            raw.set(
                raw.object(&aes, ObjectClass::SECRET_KEY),
                &[Attribute::Wrap(false)],
            );
            let ec = store.generate(EKI_KEY_ECDSA_P256, "eki-test check without protect");
            raw.set(
                raw.object(&ec, ObjectClass::PUBLIC_KEY),
                &[Attribute::Verify(false)],
            );
            for id in [aes, ec] {
                let mut info = lifecycle::prefilled_info_v2();
                let status = lifecycle::get_info_v2(store.ptr(), Some(&id), Some(&mut info));
                assert_eq!(status, EKI_ERR_BACKEND);
                assert!(!last_error(store.ptr()).is_empty(), "a message");
                lifecycle::assert_info_v2_zero(&info);
                assert_eq!(lifecycle::revoke(store.ptr(), Some(&id)), EKI_ERR_BACKEND);
            }
            // A foreign object still takes its id and can be destroyed.
            store.destroy(&aes);
            store.destroy(&ec);
        });
    }

    #[test]
    fn a_key_destroyed_elsewhere_ends_its_request() {
        with_token(|token| {
            let approvers = Approvers::new(3);
            let dual = dual_store(token, &approvers);
            let plain = Store::open(&token.config());
            let id = dual.generate(EKI_KEY_HMAC_SHA256, "eki-test vanishing");
            dual.forget(&id);
            let request = dual.request(&id);
            assert_eq!(dual.approve(&approvers, 0, &request, &id), (EKI_OK, 1));
            plain.destroy(&id);
            assert_eq!(
                dual.approve(&approvers, 1, &request, &id),
                (EKI_ERR_KEY_NOT_FOUND, 0)
            );
            assert_eq!(
                dual.approve(&approvers, 2, &request, &id),
                (EKI_ERR_KEY_NOT_FOUND, 0),
                "the request was removed"
            );
        });
    }

    #[test]
    fn pkcs11_fields_come_first_in_open_v2() {
        with_token(|token| {
            let approvers = Approvers::new(2);
            let keys = approvers.bytes(2);
            let base = token.config();
            // A NULL PKCS#11 field before the format of the approvers.
            let mut cfg = config_v2(&base, None, Some(&keys), 1);
            cfg.pkcs11_module_path = core::ptr::null();
            assert_open_v2_fails(&cfg, EKI_ERR_NULL_POINTER);
            // A NULL approver array is a NULL field too, after the PKCS#11 fields.
            let bad_label = label("");
            let mut cfg = config_v2(&base, None, None, 2);
            cfg.pkcs11_token_label = bad_label.as_ptr();
            assert_open_v2_fails(&cfg, EKI_ERR_NULL_POINTER);
            // Formats in field order, all before the module is loaded.
            let missing = label("/nonexistent/ekibridge-test-module.so");
            let mut cfg = config_v2(&base, None, Some(&keys), 1);
            cfg.pkcs11_module_path = missing.as_ptr();
            assert_open_v2_fails(&cfg, EKI_ERR_INVALID_ARGUMENT);
            let mut cfg = config_v2(&base, None, Some(&keys), 2);
            cfg.pkcs11_module_path = missing.as_ptr();
            assert_open_v2_fails(&cfg, EKI_ERR_BACKEND);
        });
    }

    #[test]
    fn a_pkcs11_handle_writes_an_audit_log() {
        with_token(|token| {
            let dir = std::env::temp_dir().join(format!(
                "ekicore-rs-ffi-lifecycle-pkcs11-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("temporary directory");
            let path = CString::new(dir.join("audit.log").as_os_str().as_bytes()).expect("no NUL");
            let store = Store::open_v2(&config_v2(&token.config(), Some(&path), None, 0));
            let id = store.generate(EKI_KEY_HMAC_SHA256, "eki-test logged");
            let _ = store.rotate(&id);
            let missing = fixed_id(0x77);
            // get_info_v2 is not logged, whatever its status.
            let mut info = lifecycle::prefilled_info_v2();
            assert_eq!(
                lifecycle::get_info_v2(store.ptr(), Some(&missing), Some(&mut info)),
                EKI_ERR_KEY_NOT_FOUND
            );
            let (head, seq) = store.audit_head();
            drop(store);
            // open, generate, rotate, then the guard's two destroys and close.
            let mut records = 0;
            assert_eq!(
                audit_verify(path.as_ptr(), None, Some(&mut records)),
                EKI_OK
            );
            assert_eq!((seq, records), (3, 6));
            let mut cut = std::fs::read(dir.join("audit.log")).expect("readable");
            let lines: Vec<usize> = cut
                .iter()
                .enumerate()
                .filter_map(|(i, &b)| (b == b'\n').then_some(i))
                .collect();
            cut.truncate(lines[2] + 1);
            std::fs::write(dir.join("audit.log"), &cut).expect("writable");
            let mut records = 0;
            assert_eq!(
                audit_verify(path.as_ptr(), Some(&head), Some(&mut records)),
                EKI_OK
            );
            assert_eq!(records, 3);
            let _ = std::fs::remove_dir_all(&dir);
        });
    }
}

/// Without the `pkcs11` feature `eki_ks_open_v2` answers for the selector before it reads any
/// field, as `eki_ks_open` does.
#[cfg(not(feature = "pkcs11"))]
mod without_pkcs11 {
    use super::common::{assert_open_v2_fails, config, config_v2};
    use ekicore_abi::{EKI_KS_PKCS11, eki_status};

    #[test]
    fn pkcs11_backend_not_compiled_in_is_unsupported() {
        let base = config(EKI_KS_PKCS11, None, None, None);
        let garbage = [0_u8; 3];
        assert_open_v2_fails(
            &config_v2(&base, None, Some(&garbage), 1),
            eki_status::EKI_ERR_UNSUPPORTED,
        );
        assert_open_v2_fails(
            &config_v2(&base, None, None, 2),
            eki_status::EKI_ERR_UNSUPPORTED,
        );
    }
}
