//! What a head statement buys, end to end, against a real store. Decision 0005.
//!
//! Each failure a statement exists to catch is made on purpose: a store that
//! holds less than a key said it had, a key that said two things at one
//! count, and a store rolled back to before what this copy already saw.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use historica::core::RevisionId;
use historica::format::digest;
use historica::record::{Clock, Kinds, Platform, Recording, Restriction, record};
use historica::store::Store;
use historica::working::Working;
use historica_minisign::sign::SecretKey;
use historica_minisign::verify::{Finding, Report};
use historica_minisign::{Key, Statement, key, naming, seen, sign, trust, verify};

const PASSWORD: &str = "not a secret";

fn scratch(test: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("stating-{test}"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("a scratch directory");
    path
}

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
            kinds: Kinds::default(),
            extensions: BTreeMap::new(),
        };
        record(&mut store, &working, &recording, &mut Platform).expect("a revision");
    }
    store
}

fn keys(directory: &Path, name: &str) -> (SecretKey, Key) {
    let home = directory.join(name);
    let generated = key::generate(&home, Some(PASSWORD.to_owned())).expect("a key pair");
    let secret = key::load(&generated.secret, Some(PASSWORD.to_owned())).expect("the key back");
    (secret, generated.key)
}

fn believe(store: &Store, key: &Key, label: &str) {
    trust::add(
        store.filesystem(),
        store.root(),
        label,
        &trust::Entry {
            key: key.clone(),
            who: format!("{label} <{label}@example.com>"),
        },
    )
    .expect("the policy written");
}

fn reopen(store: &Store) -> Store {
    Store::open(store.root()).expect("the store reopened")
}

/// State `heads` at `counter`, filed as `state` would file it.
fn state_these(
    store: &Store,
    secret: &SecretKey,
    heads: BTreeSet<RevisionId>,
    counter: u64,
) -> Statement {
    let statement = sign::statement_for(heads, counter, secret, &Platform).expect("a statement");
    let report = verify::verify(store).expect("a report");
    let existing: Vec<(RevisionId, Statement)> = report
        .statements()
        .iter()
        .map(|held| (held.statement.digest(), held.statement.clone()))
        .collect();
    let stem = naming::statement_stem(
        &statement.digest(),
        &statement,
        existing
            .iter()
            .map(|(digest, statement)| (digest, statement)),
    );
    sign::write_statement(store.filesystem(), store.root(), &statement, &stem, secret)
        .expect("it written");
    statement
}

/// What `historica-minisign state` does: every head, one count higher.
fn state(store: &Store, secret: &SecretKey) -> Statement {
    let key = sign::public_key(secret).expect("a key");
    let report = verify::verify(store).expect("a report");
    let counter = report
        .highest_counter(&key)
        .map_or(1, |highest| highest + 1);
    state_these(store, secret, store.history().heads(), counter)
}

fn report(store: &Store) -> Report {
    verify::verify(&reopen(store)).expect("a report")
}

fn errors(report: &Report) -> Vec<Finding> {
    report.errors().cloned().collect()
}

#[test]
fn a_statement_by_a_believed_key_verifies_and_counts_up() {
    let directory = scratch("counts-up");
    let store = store_of(&directory, 2);
    let (secret, key) = keys(&directory, "keys");
    believe(&store, &key, "adam");

    assert_eq!(state(&store, &secret).counter, 1);
    assert_eq!(state(&store, &secret).counter, 2);

    let report = report(&store);
    assert!(report.ok(), "{:?}", errors(&report));
    let latest: Vec<_> = report.latest().collect();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].1.statement.counter, 2);
    assert!(latest[0].1.path.ends_with(format!(
        "claims/heads/{}/2.heads.txt",
        naming::key_prefix(&key)
    )));
}

#[test]
fn a_store_holding_less_than_a_key_stated_is_an_error() {
    let directory = scratch("withheld");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory, "keys");
    believe(&store, &key, "adam");

    let elsewhere = digest(b"a revision this store was never shown");
    let mut heads = store.history().heads();
    heads.insert(elsewhere);
    state_these(&store, &secret, heads, 1);

    let report = report(&store);
    assert!(
        errors(&report)
            .iter()
            .any(|finding| matches!(finding, Finding::Withheld { revision, .. } if *revision == elsewhere)),
        "{:?}",
        errors(&report)
    );
}

#[test]
fn a_key_nobody_believes_cannot_fail_the_store() {
    let directory = scratch("untrusted");
    let store = store_of(&directory, 1);
    let (secret, _) = keys(&directory, "keys");

    let mut heads = store.history().heads();
    heads.insert(digest(b"nothing"));
    state_these(&store, &secret, heads.clone(), 1);
    heads.insert(digest(b"something else"));
    state_these(&store, &secret, heads, 1);

    let report = report(&store);
    assert!(report.ok(), "{:?}", errors(&report));
    assert!(
        report
            .notes()
            .any(|finding| matches!(finding, Finding::Untrusted { .. }))
    );
}

#[test]
fn two_statements_at_one_count_are_an_equivocation() {
    let directory = scratch("equivocated");
    let store = store_of(&directory, 2);
    let (secret, key) = keys(&directory, "keys");
    believe(&store, &key, "adam");

    let all = store.history().heads();
    let one = state_these(&store, &secret, all.clone(), 1);
    let mut more = all;
    more.insert(digest(b"a second story"));
    let two = state_these(&store, &secret, more, 1);
    assert_ne!(one.digest(), two.digest());

    let report = report(&store);
    assert!(
        errors(&report)
            .iter()
            .any(|finding| matches!(finding, Finding::Equivocated { counter: 1, .. })),
        "{:?}",
        errors(&report)
    );
    // Both were filed: the second under the digest tier.
    let directory = store
        .root()
        .join("claims/heads")
        .join(naming::key_prefix(&key));
    let names: Vec<String> = fs::read_dir(directory)
        .expect("the key's directory")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".heads.txt"))
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
}

#[test]
fn a_store_rolled_back_past_what_was_witnessed_is_refused() {
    let directory = scratch("rolled-back");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory, "keys");
    believe(&store, &key, "adam");

    state(&store, &secret);
    let second = state(&store, &secret);
    let written =
        seen::witness(store.filesystem(), store.root(), &report(&store)).expect("witnessed");
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].counter, 2);
    assert_eq!(written[0].statement, second.digest());

    // Witnessing again changes nothing: a record only goes up.
    assert!(
        seen::witness(store.filesystem(), store.root(), &report(&store))
            .expect("witnessed")
            .is_empty()
    );

    // The store loses its latest statement, as one handed over by somebody
    // who would rather this copy had not seen it.
    let stem = format!("{}/2", naming::key_prefix(&key));
    fs::remove_file(historica_minisign::layout::statement_file(
        store.root(),
        &stem,
    ))
    .unwrap();
    fs::remove_file(historica_minisign::layout::statement_signature_file(
        store.root(),
        &stem,
    ))
    .unwrap();

    let report = report(&store);
    assert!(
        errors(&report).iter().any(|finding| matches!(
            finding,
            Finding::RolledBack {
                seen: 2,
                found: Some(1),
                ..
            }
        )),
        "{:?}",
        errors(&report)
    );
    // And a faulted key is not witnessed at its lower count.
    assert!(
        seen::witness(store.filesystem(), store.root(), &report)
            .expect("witnessed")
            .is_empty()
    );
    assert_eq!(
        report.seen().get(&key).map(|record| record.counter),
        Some(2)
    );
}

#[test]
fn a_statement_without_its_signature_is_an_error() {
    let directory = scratch("unsigned");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory, "keys");
    believe(&store, &key, "adam");
    state(&store, &secret);

    let stem = format!("{}/1", naming::key_prefix(&key));
    fs::remove_file(historica_minisign::layout::statement_signature_file(
        store.root(),
        &stem,
    ))
    .unwrap();

    let report = report(&store);
    assert!(
        errors(&report)
            .iter()
            .any(|finding| matches!(finding, Finding::Unsigned { .. })),
        "{:?}",
        errors(&report)
    );
    assert_eq!(report.latest().count(), 0);
}

#[test]
fn the_next_count_is_above_what_was_witnessed_even_if_the_store_forgot() {
    let directory = scratch("next-count");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory, "keys");
    believe(&store, &key, "adam");
    state(&store, &secret);
    state(&store, &secret);
    seen::witness(store.filesystem(), store.root(), &report(&store)).expect("witnessed");

    fs::remove_dir_all(store.root().join("claims/heads")).unwrap();
    assert_eq!(report(&store).highest_counter(&key), Some(2));
    assert_eq!(state(&reopen(&store), &secret).counter, 3);
}
