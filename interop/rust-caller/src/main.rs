//! Runtime-selection example: loads a libekicore build by path and drives it through the C ABI.
//! Filled in by package S6.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("usage: rust-caller <path-to-libekicore>");
    ExitCode::from(2)
}
