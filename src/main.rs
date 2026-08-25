//! `historica-sign`, the trust layer Historica's decision 0046 declined to
//! build inside Historica.
//!
//! The whole program is four commands over files a person could write by hand:
//! a claim is text, its signature is minisign's, and the policy saying whose
//! word to take is a directory of text files. Nothing here reaches inside
//! Historica — the library is asked which revisions exist and where the store
//! is, and nothing else.

mod cli;

use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run(std::env::args().skip(1)) {
        Ok(code) => ExitCode::from(code),
        Err(failure) => {
            if let Some(message) = failure.message() {
                eprintln!("historica-sign: {message}");
            }
            if failure.wants_usage() {
                eprintln!();
                eprint!("{}", cli::USAGE);
            }
            ExitCode::from(failure.code())
        }
    }
}
