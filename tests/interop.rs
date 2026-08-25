//! What this tool writes is what `minisign` writes, and the reverse.
//!
//! Decision 0001 puts one condition on decision 0002's choice to link the
//! library rather than call the command: the artifacts must be
//! indistinguishable, in both directions. A claim signed here verifies with
//! `minisign -Vm`, and a claim signed with `minisign -Sm` verifies here.
//!
//! That is the property that makes decision 0046's promise true — "checking a
//! claim by hand is two commands and neither is Historica" — so it is pinned
//! here rather than asserted in prose. Every test skips when `minisign` is not
//! on `PATH`, because a machine without it must still be able to run the suite
//! green: the person who has minisign installed is exactly the person whose
//! machine this needs to be checked on.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use historica::format::digest;
use historica::fs::Disk;
use historica::record::{Clock, Platform};
use historica_sign::claim::Claim;
use historica_sign::{key, layout, sign, verify};

const PASSWORD: &str = "not a secret";

/// Whether the real thing is here to be checked against.
fn minisign() -> bool {
    Command::new("minisign")
        .arg("-v")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn scratch(test: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("interop-{test}"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("a scratch directory");
    path
}

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new("minisign")
        .args(arguments)
        .output()
        .expect("minisign, which was on PATH a moment ago")
}

/// A revision digest that is not a revision. Nothing here opens a store: the
/// question is about two files and a signature over one of them.
fn some_revision() -> historica::core::RevisionId {
    digest(b"a revision document, somewhere")
}

#[test]
fn a_claim_this_tool_signed_verifies_with_the_minisign_command() {
    if !minisign() {
        eprintln!("skipped: minisign is not on PATH");
        return;
    }
    let directory = scratch("ours-theirs");
    let generated =
        key::generate(&directory.join("keys"), Some(PASSWORD.to_owned())).expect("a key pair");
    let secret = key::load(&generated.secret, Some(PASSWORD.to_owned())).expect("the key back");

    let claim = sign::claim_for(
        some_revision(),
        "reviewer".parse().expect("a role"),
        &secret,
        &Platform,
    )
    .expect("a claim");
    let written = sign::write(&Disk, &directory, &claim, &secret).expect("it written");

    let checked = run(&[
        "-V",
        "-m",
        written.claim.to_str().unwrap(),
        "-P",
        generated.key.as_str(),
    ]);
    assert!(
        checked.status.success(),
        "minisign refused a signature this crate wrote: {}",
        String::from_utf8_lossy(&checked.stderr)
    );

    // The signature was found beside the claim without being named, which is
    // the whole reason the suffix is `.minisig`.
    assert!(written.signature.exists());
}

#[test]
fn a_claim_the_minisign_command_signed_verifies_here() {
    if !minisign() {
        eprintln!("skipped: minisign is not on PATH");
        return;
    }
    let directory = scratch("theirs-ours");
    let keys = directory.join("keys");
    fs::create_dir_all(&keys).expect("a key directory");
    let secret = keys.join("minisign.key");
    let public = keys.join("minisign.pub");

    // `-W` writes a key with no password, which is the only way to drive the
    // command without a terminal. This is about the file format, not about how
    // anybody should keep a key.
    let generated = run(&[
        "-G",
        "-W",
        "-p",
        public.to_str().unwrap(),
        "-s",
        secret.to_str().unwrap(),
    ]);
    assert!(
        generated.status.success(),
        "minisign -G: {}",
        String::from_utf8_lossy(&generated.stderr)
    );

    // The public key as the command spells it, which is what a claim spells.
    let text = fs::read_to_string(&public).expect("the public key");
    let key: historica_sign::Key = text
        .lines()
        .find_map(|line| line.trim().parse().ok())
        .expect("a key on one of its two lines");

    let claim = Claim {
        revision: some_revision(),
        role: "release".parse().expect("a role"),
        key,
        when: Platform.now().expect("a clock"),
    };
    let bytes = claim.render().into_bytes();
    let path = directory.join(format!("{}{}", claim.digest(), layout::CLAIM_SUFFIX));
    fs::write(&path, &bytes).expect("the claim");

    let signed = run(&[
        "-S",
        "-m",
        path.to_str().unwrap(),
        "-s",
        secret.to_str().unwrap(),
    ]);
    assert!(
        signed.status.success(),
        "minisign -S: {}",
        String::from_utf8_lossy(&signed.stderr)
    );

    let signature = PathBuf::from(format!("{}{}", path.display(), layout::SIGNATURE_SUFFIX));
    assert!(
        signature.exists(),
        "minisign put its signature where this crate looks for one"
    );

    // Checked through the crate's own door rather than a second decoder, so
    // this test cannot pass by being more generous than `verify` is.
    let text = fs::read_to_string(&signature).expect("the signature");
    assert_eq!(
        verify::check_signature(&bytes, &text, &claim.key),
        Ok(()),
        "this crate refused a signature minisign wrote"
    );
}
