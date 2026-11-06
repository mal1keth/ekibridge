//! Metadata functions: `eki_abi_version`, `eki_version`, `eki_status_name` (plan §4.1, §4.2
//! "Versions", §4.4 `status_name` row).

mod common;

use common::Report;
use ekicore_conformance::{EKI_ABI_VERSION, status, status_name};

#[test]
fn abi_version_is_2_in_both() {
    let Some((a, b)) = common::setup("meta::abi_version") else {
        return;
    };
    let mut r = Report::new("meta::abi_version");
    for lib in [a, b] {
        let v = lib.abi_version();
        r.check(v == EKI_ABI_VERSION && v == 2, || {
            format!("{}: eki_abi_version() = {v}, want 2", lib.name())
        });
    }
    r.finish();
}

#[test]
fn version_strings_name_the_implementation_and_agree() {
    let Some((a, b)) = common::setup("meta::version") else {
        return;
    };
    let mut r = Report::new("meta::version");
    let mut semver = Vec::new();
    for (lib, want_impl) in [(a, "ekicore-cpp"), (b, "ekicore-rs")] {
        let Some(v) = lib.version() else {
            r.check(false, || {
                format!("{}: eki_version() returned NULL", lib.name())
            });
            continue;
        };
        let rest = v.strip_prefix(want_impl).and_then(|s| s.strip_prefix(' '));
        let ok = r.check(rest.is_some(), || {
            format!(
                "{}: eki_version() = {v:?}, want \"{want_impl} <semver>\" (is EKI_CPP_LIB / \
                 EKI_RS_LIB swapped?)",
                lib.name()
            )
        });
        if ok {
            let x = rest.unwrap_or_default().to_owned();
            r.check(x == env!("CARGO_PKG_VERSION"), || {
                format!(
                    "{}: version {x:?} differs from the workspace version {:?}",
                    lib.name(),
                    env!("CARGO_PKG_VERSION")
                )
            });
            semver.push(x);
        }
    }
    if semver.len() == 2 {
        r.check(semver[0] == semver[1], || {
            format!(
                "version suffixes differ: {:?} vs {:?}",
                semver[0], semver[1]
            )
        });
    }
    r.finish();
}

#[test]
fn status_name_matches_the_harness_table() {
    let Some((a, b)) = common::setup("meta::status_name") else {
        return;
    };
    let mut r = Report::new("meta::status_name");
    let mut inputs: Vec<i32> = (0..=13).collect();
    inputs.extend([-1, i32::MIN, i32::MAX, 99]);
    for lib in [a, b] {
        for s in inputs.iter().copied() {
            let want = status_name(s);
            match lib.status_name(s) {
                None => {
                    r.check(false, || {
                        format!("{}: eki_status_name({s}) returned NULL", lib.name())
                    });
                }
                Some(got) => {
                    r.check(got == want, || {
                        format!(
                            "{}: eki_status_name({s}) = {got:?}, want {want:?}",
                            lib.name()
                        )
                    });
                }
            }
        }
    }
    // §4.4 and the ABI 2 contract §7: these five map to the unknown name.
    for s in [-1, i32::MIN, i32::MAX, 13, 99] {
        r.check(status_name(s) == status::UNKNOWN_NAME, || {
            format!("harness table maps {s} to {}", status_name(s))
        });
    }
    r.finish();
}
