//! The commands, as a person meets them.
//!
//! Exit codes are part of the interface here rather than an afterthought:
//! `verify --complete` failing is how a store's own CI refuses history nobody
//! has vouched for, which is decision 0046's deferred enforcement done from the
//! outside, where this tool is allowed to do it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use historica::record::{Clock, Kinds, Platform, Recording, Restriction, record};
use historica::store::Store;
use historica::working::Working;

const PASSWORD: &str = "not a secret";

fn scratch(test: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-{test}"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("a scratch directory");
    path
}

/// A folder with a store in it and one revision recorded, and a password file
/// beside it.
fn work(directory: &Path) -> PathBuf {
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
    fs::write(directory.join("password"), PASSWORD).expect("a password file");
    folder
}

fn run(folder: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_historica-sign"))
        .arg("-C")
        .arg(folder)
        .args(arguments)
        .output()
        .expect("the binary this test crate builds")
}

fn out(folder: &Path, arguments: &[&str]) -> String {
    let output = run(folder, arguments);
    assert!(
        output.status.success(),
        "`{}` failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("printed text")
}

/// Make a key pair in `directory` and hand back its public key line.
fn key(directory: &Path) -> String {
    let keys = directory.join("keys");
    let password = directory.join("password");
    let printed = out(
        directory,
        &[
            "key",
            "new",
            "--at",
            keys.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ],
    );
    printed
        .lines()
        .next()
        .expect("the key on the first line")
        .to_owned()
}

#[test]
fn a_store_nobody_has_vouched_for_verifies_but_is_not_complete() {
    let directory = scratch("empty");
    let folder = work(&directory);

    assert!(run(&folder, &["verify"]).status.success());
    let refused = run(&folder, &["verify", "--complete"]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&refused.stdout).contains("no trusted key vouches"),
        "the refusal says which head, on stdout, where the report is"
    );
}

#[test]
fn signing_and_then_believing_the_key_makes_a_store_complete() {
    let directory = scratch("whole");
    let folder = work(&directory);
    let key = key(&directory);
    let secret = directory.join("keys/minisign.key");
    let password = directory.join("password");

    let signed = out(
        &folder,
        &[
            "sign",
            "--key",
            secret.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ],
    );
    assert!(signed.contains("vouches for"));
    assert!(
        signed.contains("nothing in trust/ speaks for that key"),
        "signing says plainly that this copy does not yet believe the signer"
    );

    // Signed but not believed: still not complete.
    assert_eq!(
        run(&folder, &["verify", "--complete"]).status.code(),
        Some(1)
    );

    out(
        &folder,
        &["trust", "add", &key, "The Test <test@example.com>"],
    );
    assert!(out(&folder, &["trust", "list"]).contains("The Test"));

    let verified = out(&folder, &["verify", "--complete"]);
    assert!(
        verified.contains("1 claim, 1 by a key this copy believes"),
        "{verified}"
    );
    assert!(
        verified.contains("1 of 1 revisions are vouched for"),
        "{verified}"
    );
}

#[test]
fn verify_asks_about_one_revision_when_told_to() {
    let directory = scratch("one-revision");
    let folder = work(&directory);
    let key = key(&directory);
    let secret = directory.join("keys/minisign.key");
    let password = directory.join("password");
    out(
        &folder,
        &["trust", "add", &key, "The Test <test@example.com>"],
    );

    let head = Store::discover(&folder)
        .expect("the store")
        .history()
        .heads()
        .into_iter()
        .next()
        .expect("a head");

    assert_eq!(
        run(&folder, &["verify", &head.to_string()]).status.code(),
        Some(1),
        "a revision nobody vouches for is not a passing answer to `is this vouched for`"
    );

    out(
        &folder,
        &[
            "sign",
            &head.to_string(),
            "--role",
            "reviewer",
            "--key",
            secret.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ],
    );

    let printed = out(&folder, &["verify", &head.to_string()]);
    assert!(printed.contains("is vouched for"), "{printed}");
    assert!(printed.contains("as reviewer"), "{printed}");
}

#[test]
fn a_key_is_never_overwritten() {
    let directory = scratch("key-twice");
    work(&directory);
    key(&directory);

    let again = run(
        &directory,
        &[
            "key",
            "new",
            "--at",
            directory.join("keys").to_str().unwrap(),
            "--password-file",
            directory.join("password").to_str().unwrap(),
        ],
    );
    assert_eq!(again.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("destroys every signature"),
        "the refusal says what overwriting a key would cost"
    );
}

#[test]
fn a_label_can_be_chosen_and_removed() {
    let directory = scratch("labels");
    let folder = work(&directory);
    let key = key(&directory);

    out(
        &folder,
        &[
            "trust",
            "add",
            &key,
            "The Test <test@example.com>",
            "--label",
            "the-test",
        ],
    );
    assert!(out(&folder, &["trust", "list"]).starts_with("the-test  "));
    out(&folder, &["trust", "remove", "the-test"]);
    assert!(out(&folder, &["trust", "list"]).contains("believes nobody yet"));
}

#[test]
fn a_role_that_is_not_a_role_is_a_usage_error() {
    let directory = scratch("bad-role");
    let folder = work(&directory);
    let refused = run(&folder, &["sign", "--role", "Second Reviewer"]);
    assert_eq!(refused.status.code(), Some(2));
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        said.contains("a role is one to thirty-two characters"),
        "{said}"
    );
    assert!(said.contains("usage:"), "a usage error prints the usage");
}

#[test]
fn an_unknown_command_is_a_usage_error() {
    let directory = scratch("unknown");
    let folder = work(&directory);
    let refused = run(&folder, &["vouch"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("`vouch` is not a command"));
}

#[test]
fn the_usage_names_the_two_commands_that_check_a_claim_by_hand() {
    let directory = scratch("usage");
    let folder = work(&directory);
    let printed = out(&folder, &["--help"]);
    assert!(printed.contains("minisign -Vm"));
    assert!(printed.contains("shasum -a 256"));
}

/// Decision 0003's migration and repair, as a person meets it: a claim under a
/// name nobody computed is counted, told where it belongs, and moved there.
#[test]
fn arrange_files_a_hand_written_claim_where_it_belongs() {
    let directory = scratch("arrange");
    let folder = work(&directory);
    let public = key(&directory);
    let secret = directory.join("keys").join("minisign.key");
    let password = directory.join("password");

    out(
        &folder,
        &["trust", "add", &public, "Adam Harris <adam@example.com>"],
    );
    out(
        &folder,
        &[
            "sign",
            "--key",
            secret.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ],
    );

    // Move the claim and its signature somewhere nobody would compute, which is
    // exactly what a person writing one by hand produces.
    let claims = folder.join("history").join("claims");
    let filed = under(&claims);
    assert_eq!(filed.len(), 2, "one claim and one signature: {filed:?}");
    for path in &filed {
        let name = path.file_name().and_then(|name| name.to_str()).unwrap();
        let moved =
            claims.join(name.replace(name.split(".claim.txt").next().unwrap(), "a claim I wrote"));
        fs::rename(path, &moved).expect("it moved");
    }

    let printed = out(&folder, &["verify"]);
    assert!(
        printed.contains("1 claim, 1 by a key this copy believes"),
        "{printed}"
    );
    assert!(printed.contains("belongs at"), "{printed}");

    let dry = out(&folder, &["arrange", "--dry-run"]);
    assert!(dry.contains("would move"), "{dry}");
    assert_eq!(under(&claims).len(), 2, "--dry-run moves nothing");

    let done = out(&folder, &["arrange"]);
    assert!(done.contains("moved"), "{done}");

    let after = under(&claims);
    assert_eq!(
        after.len(),
        2,
        "still one claim and one signature: {after:?}"
    );
    assert!(
        after
            .iter()
            .all(|path| !path.to_str().unwrap().contains("a claim I wrote")),
        "{after:?}"
    );

    let printed = out(&folder, &["verify"]);
    assert!(
        printed.contains("1 claim, 1 by a key this copy believes"),
        "{printed}"
    );
    assert!(
        !printed.contains("belongs at"),
        "arranged is arranged: {printed}"
    );
}

/// Every file under a directory, at any depth.
fn under(directory: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(directory) else {
        return out;
    };
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            out.extend(under(&entry.path()));
        } else {
            out.push(entry.path());
        }
    }
    out.sort();
    out
}

/// A duplicate is left alone unless asked about, and what `--prune` deletes is
/// checked byte for byte first.
#[test]
fn arrange_prunes_a_duplicate_only_when_asked() {
    let directory = scratch("prune");
    let folder = work(&directory);
    let public = key(&directory);
    let secret = directory.join("keys").join("minisign.key");
    let password = directory.join("password");

    out(
        &folder,
        &["trust", "add", &public, "Adam Harris <adam@example.com>"],
    );
    out(
        &folder,
        &[
            "sign",
            "--key",
            secret.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
        ],
    );

    // The same claim again under another name, which is what a copy that had
    // not yet received the revision would have written.
    let claims = folder.join("history").join("claims");
    for path in under(&claims) {
        let name = path.file_name().and_then(|name| name.to_str()).unwrap();
        let copy = claims.join(name.replace(
            name.split(".claim.txt").next().unwrap(),
            "the same claim twice",
        ));
        fs::copy(&path, &copy).expect("a duplicate");
    }
    assert_eq!(under(&claims).len(), 4);

    let printed = out(&folder, &["verify"]);
    assert!(
        printed.contains("1 claim, 1 by a key this copy believes"),
        "{printed}"
    );
    assert!(printed.contains("counted once"), "{printed}");

    let left = out(&folder, &["arrange"]);
    assert!(left.contains("--prune deletes"), "{left}");
    assert_eq!(under(&claims).len(), 4, "arrange alone deletes nothing");

    let pruned = out(&folder, &["arrange", "--prune"]);
    assert!(pruned.contains("deleted"), "{pruned}");
    assert_eq!(under(&claims).len(), 2, "one claim and one signature");

    let printed = out(&folder, &["verify"]);
    assert!(
        printed.contains("1 claim, 1 by a key this copy believes"),
        "{printed}"
    );
    assert!(
        printed.contains("1 of 1 revisions are vouched for"),
        "{printed}"
    );
}
