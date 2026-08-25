//! What a claim buys, end to end, against a real store.
//!
//! The claims under test are decision 0046's, in its own order: a claim over a
//! revision covers the whole ancestry behind it; a claim by a key the policy
//! does not hold is a note and not an error; and a store with no claims at all
//! verifies vacuously. Everything that says *the store holds something wrong*
//! is exercised by damaging a store on purpose, because the whole worth of the
//! design is what it does when somebody has.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use historica::core::RevisionId;
use historica::record::{Clock, Platform, Recording, Restriction, record};
use historica::store::Store;
use historica::working::Working;
use historica_sign::claim::{Claim, Role};
use historica_sign::sign::SecretKey;
use historica_sign::verify::Finding;
use historica_sign::{key, layout, sign, trust, verify};

/// A password no test keeps a secret, in a file, which is the only way to sign
/// without a terminal.
const PASSWORD: &str = "not a secret";

fn scratch(test: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("vouching-{test}"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("a scratch directory");
    path
}

/// A store of `revisions` revisions over one file, each descending from the
/// last.
fn store_of(directory: &Path, revisions: usize) -> Store {
    let folder = directory.join("work");
    fs::create_dir_all(&folder).expect("a folder");
    let mut store = Store::init(folder.join("history")).expect("a store");

    for step in 0..revisions {
        fs::write(folder.join("notes.txt"), format!("line {step}\n")).expect("a file");
        let working = Working::read(&folder, store.skipped()).expect("the folder");
        let recording = Recording {
            parents: store.history().heads().into_iter().collect(),
            author: "Adam Harris <adam@example.com>".to_owned(),
            when: Platform.now().expect("a clock"),
            message: format!("step {step}"),
            moves: Vec::new(),
            at: Vec::new(),
            accepted: BTreeSet::new(),
            only: Restriction::Everything,
        };
        record(&mut store, &working, &recording, &mut Platform).expect("a revision");
    }
    store
}

/// A key pair in its own directory, unlocked.
fn keys(directory: &Path) -> (SecretKey, historica_sign::Key) {
    let home = directory.join("keys");
    let generated = key::generate(&home, Some(PASSWORD.to_owned())).expect("a key pair");
    let secret = key::load(&generated.secret, Some(PASSWORD.to_owned())).expect("the key back");
    (secret, generated.key)
}

fn head(store: &Store) -> RevisionId {
    let heads = verify::current_heads(store);
    assert_eq!(heads.len(), 1, "these fixtures are one line of work");
    heads.into_iter().next().expect("a head")
}

fn vouch(store: &Store, revision: RevisionId, role: &str, secret: &SecretKey) -> Claim {
    let claim = sign::claim_for(
        revision,
        role.parse::<Role>().expect("a role"),
        secret,
        &Platform,
    )
    .expect("a claim");
    sign::write(store.filesystem(), store.root(), &claim, secret).expect("it written");
    claim
}

fn believe(store: &Store, key: &historica_sign::Key) {
    trust::add(
        store.filesystem(),
        store.root(),
        "tester",
        &trust::Entry {
            key: key.clone(),
            who: "The Test <test@example.com>".to_owned(),
        },
    )
    .expect("the policy written");
}

/// Reopened, because `verify` reads the directories and the store's own view of
/// them was taken before anything was written.
fn reopen(store: &Store) -> Store {
    Store::open(store.root()).expect("the store again")
}

#[test]
fn a_store_with_no_claims_verifies_vacuously() {
    let directory = scratch("vacuous");
    let store = store_of(&directory, 2);
    let report = verify::verify(&store).expect("a report");

    assert!(
        report.ok(),
        "a store nobody has vouched for is not a wrong one"
    );
    assert_eq!(report.held().len(), 0);
    // It is not *complete*, though, and the difference is the whole of what
    // `--complete` is for.
    assert!(!report.complete());
    assert!(
        report
            .notes()
            .any(|finding| matches!(finding, Finding::Unvouched { .. }))
    );
}

#[test]
fn a_claim_by_an_unknown_key_is_a_note_and_not_an_error() {
    let directory = scratch("unknown-key");
    let store = store_of(&directory, 2);
    let (secret, _) = keys(&directory);
    vouch(&store, head(&store), "author", &secret);

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(
        report.ok(),
        "the store is intact; this copy just has no opinion"
    );
    assert_eq!(report.held().len(), 1);
    assert!(report.held()[0].verified, "the signature is real");
    assert!(!report.held()[0].counts(), "and it counts for nothing yet");
    assert!(
        report
            .notes()
            .any(|finding| matches!(finding, Finding::Untrusted { .. }))
    );
    assert_eq!(report.vouched().len(), 0);
}

#[test]
fn vouching_for_the_head_vouches_for_the_history_behind_it() {
    let directory = scratch("ancestry");
    let store = store_of(&directory, 4);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    vouch(&store, head(&store), "author", &secret);

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(report.ok());
    assert!(
        report.complete(),
        "{:?}",
        report.findings().collect::<Vec<_>>()
    );
    assert_eq!(
        report.vouched().len(),
        4,
        "one claim, and the whole ancestry behind it"
    );
    assert_eq!(report.revisions(), 4);
}

#[test]
fn vouching_for_a_middle_revision_leaves_the_head_unvouched() {
    let directory = scratch("partial");
    let store = store_of(&directory, 3);
    let (secret, key) = keys(&directory);
    believe(&store, &key);

    // The oldest revision: the one everything else descends from, which is the
    // one that covers the least.
    let oldest = *store
        .iter()
        .find(|(_, document)| document.parents.is_empty())
        .expect("a root")
        .0;
    vouch(&store, oldest, "author", &secret);

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(report.ok());
    assert!(!report.complete());
    assert_eq!(report.vouched().len(), 1);
    assert!(report.vouches_for(&oldest));
    assert!(!report.vouches_for(&head(&store)));
}

#[test]
fn signing_the_same_revision_twice_writes_one_file() {
    let directory = scratch("idempotent");
    let store = store_of(&directory, 1);
    let (secret, _) = keys(&directory);
    let claim = sign::claim_for(head(&store), "author".parse().unwrap(), &secret, &Platform)
        .expect("a claim");

    let first = sign::write(store.filesystem(), store.root(), &claim, &secret).expect("written");
    let second = sign::write(store.filesystem(), store.root(), &claim, &secret).expect("again");

    assert!(!first.already);
    assert!(
        second.already,
        "the same claim is the same bytes and the same file"
    );
    assert_eq!(first.claim, second.claim);
    assert_eq!(
        fs::read_dir(layout::claims(store.root()))
            .expect("the directory")
            .count(),
        2,
        "one claim and one signature"
    );
}

#[test]
fn a_claim_whose_name_lies_is_an_error() {
    let directory = scratch("false-name");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let claim = vouch(&store, head(&store), "author", &secret);

    // Edit the claim under its own name: the role changes, the digest in the
    // filename does not.
    let path = layout::claim_file(store.root(), &claim.digest());
    let text = fs::read_to_string(&path).expect("the claim");
    fs::write(&path, text.replace("role author", "role release")).expect("it damaged");

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(!report.ok());
    assert!(
        report
            .errors()
            .any(|finding| matches!(finding, Finding::NameIsFalse { .. })),
        "{:?}",
        report.findings().collect::<Vec<_>>()
    );
    assert_eq!(
        report.vouched().len(),
        0,
        "nothing damaged vouches for anything"
    );
}

#[test]
fn a_claim_with_no_signature_is_an_error() {
    let directory = scratch("unsigned");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let claim = vouch(&store, head(&store), "author", &secret);

    fs::remove_file(layout::signature_file(store.root(), &claim.digest()))
        .expect("the signature removed");

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(
        !report.ok(),
        "a claim with nothing backing it is not an observation"
    );
    assert!(
        report
            .errors()
            .any(|finding| matches!(finding, Finding::Unsigned { .. }))
    );
    assert_eq!(report.vouched().len(), 0);
}

#[test]
fn a_signature_with_no_claim_is_an_error() {
    let directory = scratch("orphan");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let claim = vouch(&store, head(&store), "author", &secret);

    fs::remove_file(layout::claim_file(store.root(), &claim.digest())).expect("the claim removed");

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(!report.ok());
    assert!(
        report
            .errors()
            .any(|finding| matches!(finding, Finding::Orphaned { .. }))
    );
}

#[test]
fn a_signature_by_another_key_is_refused() {
    let directory = scratch("wrong-key");
    let store = store_of(&directory, 1);
    let (mine, my_key) = keys(&directory);
    let (_, their_key) = {
        let elsewhere = directory.join("theirs");
        let generated =
            key::generate(&elsewhere, Some(PASSWORD.to_owned())).expect("another key pair");
        (
            key::load(&generated.secret, Some(PASSWORD.to_owned())).expect("it back"),
            generated.key,
        )
    };
    believe(&store, &their_key);

    // A claim in their name, signed with my key: the shape of somebody putting
    // words in somebody else's mouth, which the signature is the whole answer
    // to.
    let claim = Claim {
        revision: head(&store),
        role: "reviewer".parse().expect("a role"),
        key: their_key,
        when: Platform.now().expect("a clock"),
    };
    let bytes = claim.render().into_bytes();
    let digest = claim.digest();
    fs::create_dir_all(layout::claims(store.root())).expect("the directory");
    fs::write(layout::claim_file(store.root(), &digest), &bytes).expect("the claim");
    let name = format!("{digest}{}", layout::CLAIM_SUFFIX);
    fs::write(
        layout::signature_file(store.root(), &digest),
        sign::signature(&mine, &bytes, &name).expect("a signature"),
    )
    .expect("the signature");

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(!report.ok());
    assert!(
        report
            .errors()
            .any(|finding| matches!(finding, Finding::Refused { .. })),
        "{:?}",
        report.findings().collect::<Vec<_>>()
    );
    assert_eq!(report.vouched().len(), 0);
    let _ = my_key;
}

#[test]
fn a_claim_for_a_revision_this_store_does_not_hold_is_a_note() {
    let directory = scratch("absent");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);

    // A digest of something that is not a revision here: claims travel by file
    // sync and history travels by `receive`, so one arriving first is ordinary.
    let elsewhere = historica::format::digest(b"a revision in somebody else's store");
    vouch(&store, elsewhere, "author", &secret);

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(report.ok(), "arriving out of order is not damage");
    assert!(
        report
            .notes()
            .any(|finding| matches!(finding, Finding::Absent { .. }))
    );
    assert_eq!(report.vouched().len(), 0);
}

#[test]
fn a_trust_file_that_is_not_an_entry_is_an_error() {
    let directory = scratch("bad-policy");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    vouch(&store, head(&store), "author", &secret);

    fs::write(
        layout::trust(store.root()).join("broken.txt"),
        "trust-0\nkey not-a-key\nwho Nobody\n",
    )
    .expect("a broken entry");

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(!report.ok());
    assert!(
        report
            .errors()
            .any(|finding| matches!(finding, Finding::MalformedTrust { .. }))
    );
    // The good entry still counts: one unreadable file does not empty a policy.
    assert!(!report.vouched().is_empty());
}

#[test]
fn a_label_is_never_overwritten() {
    let directory = scratch("labels");
    let store = store_of(&directory, 1);
    let (_, key) = keys(&directory);
    believe(&store, &key);

    let again = trust::add(
        store.filesystem(),
        store.root(),
        "tester",
        &trust::Entry {
            key,
            who: "Somebody Else <else@example.com>".to_owned(),
        },
    );
    assert!(
        matches!(again, Err(trust::TrustError::Taken { .. })),
        "two additions on one machine cannot lose one"
    );
}
