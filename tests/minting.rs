//! A key kept somewhere that is not a file.
//!
//! [`key::mint`] exists for a caller whose secret store is a keychain rather
//! than a directory, and which therefore never hands this crate a path. Two
//! things have to hold for that to be worth anything, and neither is visible
//! from inside the crate:
//!
//! - the key survives the trip out to that store and back, which is
//!   `SecretKey::to_bytes` and `SecretKey::from_bytes`, because a key rebuilt
//!   on every use is rebuilt or it is nothing;
//! - what the rebuilt key signs is what `minisign -Vm` accepts, which is
//!   decision 0001's condition on decision 0002 — the artifacts are
//!   indistinguishable — and it does not stop applying because the key spent
//!   the night somewhere other than `~/.minisign`.
//!
//! The second skips when `minisign` is not on `PATH`, as `interop.rs` does and
//! for the same reason: a machine without it must still run the suite green.
//!
//! `key::load` is pinned here too: what it does with an unencrypted key file is
//! the question minting exists to answer, and the answer is not "write one of
//! those instead".

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use historica::core::RevisionId;
use historica::record::{Clock, Kinds, Platform, Recording, Restriction, record};
use historica::store::Store;
use historica::working::Working;
use historica_minisign::sign::SecretKey;
use historica_minisign::{key, naming, sign, verify};

/// Whether the real thing is here to be checked against.
fn minisign() -> bool {
    Command::new("minisign")
        .arg("-v")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn scratch(test: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("minting-{test}"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("a scratch directory");
    path
}

/// A folder with a store in it and one revision recorded.
fn work(directory: &Path) -> Store {
    let folder = directory.join("work");
    fs::create_dir_all(&folder).expect("a folder");
    let mut store = Store::init(folder.join("history")).expect("a store");
    fs::write(folder.join("notes.txt"), "one line\n").expect("a file");
    let working = Working::read(&folder, store.skipped()).expect("the folder");
    let recording = Recording {
        parents: Vec::new(),
        author: "Adam Harris <adam@example.com>".to_owned(),
        when: Platform.now().expect("a clock"),
        message: "a first line".to_owned(),
        moves: Vec::new(),
        at: Vec::new(),
        accepted: BTreeSet::new(),
        only: Restriction::Everything,
        kinds: Kinds::default(),
        extensions: BTreeMap::new(),
    };
    record(&mut store, &working, &recording, &mut Platform).expect("a revision");
    store
}

/// The key as its holder would keep it: bytes, and a key rebuilt from them.
fn through_a_secret_store(secret: &SecretKey) -> SecretKey {
    SecretKey::from_bytes(&secret.to_bytes()).expect("the key back out of its store")
}

#[test]
fn a_minted_key_is_the_same_key_after_a_trip_through_bytes() {
    let minted = key::mint().expect("a key");
    let rebuilt = through_a_secret_store(&minted);

    // The public key, not the secret bytes: it is what a claim names and what
    // a verifier is given, so it is the identity that has to survive.
    assert_eq!(
        key::public_of(&rebuilt).expect("its public key"),
        key::public_of(&minted).expect("its public key"),
        "a key rebuilt from its own bytes signs as somebody else"
    );
}

#[test]
fn a_claim_signed_with_a_minted_key_verifies_with_the_minisign_command() {
    if !minisign() {
        eprintln!("skipped: minisign is not on PATH");
        return;
    }
    let directory = scratch("minted-verifies");
    let store = work(&directory);
    let revision = verify::current_heads(&store)
        .into_iter()
        .next()
        .expect("the one head this fixture has");

    // Minted, put away, and taken back out before it is ever used — which is
    // the only shape the caller this is for ever signs in.
    let secret = through_a_secret_store(&key::mint().expect("a key"));

    let claim = sign::claim_for(
        revision,
        "author".parse().expect("a role"),
        &secret,
        &Platform,
    )
    .expect("a claim");
    let stem = naming::stem_for(
        &claim.digest(),
        &claim,
        store.documents().expect("the documents"),
        std::iter::empty::<(&RevisionId, &historica_minisign::Claim)>(),
    );
    let written =
        sign::write(store.filesystem(), store.root(), &claim, &stem, &secret).expect("it written");

    let checked = Command::new("minisign")
        .args([
            "-V",
            "-m",
            written.claim.to_str().expect("a path minisign can be told"),
            "-P",
            claim.key.as_str(),
        ])
        .output()
        .expect("minisign, which was on PATH a moment ago");
    assert!(
        checked.status.success(),
        "minisign refused a signature a minted key made: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
}

/// What [`key::load`] does with an unencrypted key file, which is why
/// [`key::mint`] is not "write one of those and read it back".
///
/// minisign's loader refuses a key with no password on it before it prompts for
/// one: `load` returns rather than blocking, and returns nothing usable either
/// way. Both spellings of such a file are refused — the two-line form
/// `minisign -G -W` writes, and the raw bytes rust-minisign's own
/// `generate_and_write_unencrypted_keypair` writes, which is not a key file at
/// all. So there is no file-shaped way for a caller with no terminal to sign,
/// and this is pinned rather than fixed: the file path is minisign's, and the
/// caller who cannot take it has [`key::mint`].
#[test]
fn load_refuses_an_unencrypted_key_file_rather_than_prompting() {
    let directory = scratch("unencrypted-file");
    let minted = key::mint().expect("a key");

    // The file `minisign -G -W` writes: a comment line and the key in base64,
    // with the KDF recorded as none.
    let boxed = directory.join(key::SECRET_KEY_FILE);
    let text = minted
        .to_box(None)
        .expect("the key in minisign's own file format")
        .to_string();
    fs::write(&boxed, &text).expect("the key file");

    let refused = key::load(&boxed, None).expect_err("no key comes back");
    assert!(
        refused.to_string().contains("Key is not encrypted"),
        "the refusal says which key it will not read: {refused}"
    );
    assert!(
        key::load(&boxed, Some("not a secret".to_owned())).is_err(),
        "a password is no help to a key that has none"
    );

    // What `KeyPair::generate_and_write_unencrypted_keypair` puts in a file:
    // the serialised key and no envelope, which `load` cannot even parse.
    let raw = directory.join("raw.key");
    fs::write(&raw, minted.to_bytes()).expect("the key file");
    assert!(
        key::load(&raw, None).is_err(),
        "raw bytes are not a key file"
    );
}
