//! What a claim buys, end to end, against a real store.
//!
//! The claims under test are decision 0046's, in its own order: a claim over a
//! revision covers the whole ancestry behind it; a claim by a key the policy
//! does not hold is a note and not an error; and a store with no claims at all
//! verifies vacuously. Everything that says *the store holds something wrong*
//! is exercised by damaging a store on purpose, because the whole worth of the
//! design is what it does when somebody has.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use historica::core::RevisionId;
use historica::record::{Clock, Kinds, Platform, Recording, Restriction, record};
use historica::store::Store;
use historica::working::Working;
use historica_minisign::claim::{Claim, ContentDigest, Role, Scope};
use historica_minisign::sign::SecretKey;
use historica_minisign::verify::Finding;
use historica_minisign::{key, layout, naming, sign, trust, verify};

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
            kinds: Kinds::default(),
            extensions: BTreeMap::new(),
        };
        record(&mut store, &working, &recording, &mut Platform).expect("a revision");
    }
    store
}

/// A key pair in its own directory, unlocked.
fn keys(directory: &Path) -> (SecretKey, historica_minisign::Key) {
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
    let stem = filed(store, &claim);
    sign::write(store.filesystem(), store.root(), &claim, &stem, secret).expect("it written");
    claim
}

/// The name decision 0003 gives a claim in this store, which is what `sign`
/// works out for itself and what a test has to work out the same way.
fn filed(store: &Store, claim: &Claim) -> String {
    naming::stem_for(
        &claim.digest(),
        claim,
        store.documents().expect("the documents"),
        std::iter::empty::<(&RevisionId, &Claim)>(),
    )
}

/// Where that claim's file is.
fn file_of(store: &Store, claim: &Claim) -> PathBuf {
    layout::claim_file(store.root(), &filed(store, claim))
}

/// Where that claim's signature is.
fn signature_of(store: &Store, claim: &Claim) -> PathBuf {
    layout::signature_file(store.root(), &filed(store, claim))
}

/// Every file under a directory, at any depth — which is what a claims
/// directory needs now that decision 0041's month sits inside it.
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

fn believe(store: &Store, key: &historica_minisign::Key) {
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
        .revisions()
        .find(|(_, revision)| revision.parents.is_empty())
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

    let stem = filed(&store, &claim);
    let first =
        sign::write(store.filesystem(), store.root(), &claim, &stem, &secret).expect("written");
    let second =
        sign::write(store.filesystem(), store.root(), &claim, &stem, &secret).expect("again");

    assert!(!first.already);
    assert!(
        second.already,
        "the same claim is the same bytes and the same file"
    );
    assert_eq!(first.claim, second.claim);
    assert_eq!(
        under(&layout::claims(store.root())).len(),
        2,
        "one claim and one signature"
    );
}

#[test]
fn a_claim_edited_under_its_own_name_is_an_error() {
    let directory = scratch("damaged");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let claim = vouch(&store, head(&store), "author", &secret);

    // Edit the claim where it lies. Decision 0003 took the digest out of the
    // name, so the name is no longer what catches this — the signature is, and
    // it is the thing that was always doing the catching.
    let path = file_of(&store, &claim);
    let text = fs::read_to_string(&path).expect("the claim");
    fs::write(&path, text.replace("role author", "role release")).expect("it damaged");

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
    assert_eq!(
        report.vouched().len(),
        0,
        "nothing damaged vouches for anything"
    );
}

/// The store this crate wrote before decision 0003, which must keep verifying
/// exactly as it did — including the one thing its names could be wrong about.
#[test]
fn a_digest_name_that_lies_is_still_an_error() {
    let directory = scratch("false-digest");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);

    let claim = sign::claim_for(head(&store), "author".parse().unwrap(), &secret, &Platform)
        .expect("a claim");
    // Filed under a digest that is not this claim's, which is the whole of the
    // assertion a digest name makes.
    let lie = historica::format::digest(b"not this claim").to_string();
    sign::write(store.filesystem(), store.root(), &claim, &lie, &secret).expect("written");

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
    assert_eq!(report.vouched().len(), 0);
}

/// A store written before decision 0003 verifies unchanged, and every claim in
/// it counts for exactly what it counted for.
#[test]
fn a_claim_under_a_true_digest_name_still_counts() {
    let directory = scratch("legacy");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);

    let claim = sign::claim_for(head(&store), "author".parse().unwrap(), &secret, &Platform)
        .expect("a claim");
    let stem = claim.digest().to_string();
    sign::write(store.filesystem(), store.root(), &claim, &stem, &secret).expect("written");

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(report.ok(), "{:?}", report.findings().collect::<Vec<_>>());
    assert!(report.vouches_for(&head(&store)));
    assert!(
        report
            .notes()
            .any(|finding| matches!(finding, Finding::Misfiled { .. })),
        "it counts, and it is still told where it belongs"
    );
}

#[test]
fn a_claim_with_no_signature_is_an_error() {
    let directory = scratch("unsigned");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let claim = vouch(&store, head(&store), "author", &secret);

    fs::remove_file(signature_of(&store, &claim)).expect("the signature removed");

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

    fs::remove_file(file_of(&store, &claim)).expect("the claim removed");

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
        scope: Scope::Revision,
        role: "reviewer".parse().expect("a role"),
        key: their_key,
        when: Platform.now().expect("a clock"),
    };
    let bytes = claim.render().into_bytes();
    let path = file_of(&store, &claim);
    fs::create_dir_all(path.parent().expect("a directory")).expect("the directory");
    fs::write(&path, &bytes).expect("the claim");
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a name")
        .to_owned();
    fs::write(
        signature_of(&store, &claim),
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

// ---------------------------------------------------------------------------
// Decision 0003: where a claim is filed, and what reads it
// ---------------------------------------------------------------------------

#[test]
fn a_claim_is_filed_beside_the_revision_it_vouches_for() {
    let directory = scratch("filed");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let claim = vouch(&store, head(&store), "author", &secret);

    let path = file_of(&store, &claim);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a name");

    assert!(
        name.ends_with(" — author.claim.txt"),
        "the role is what the name ends with: {name}"
    );
    assert!(
        !name.starts_with(&claim.digest().to_string()),
        "a folder of hashes is what this decision was about: {name}"
    );
    // Decision 0041's month directory, taken from the revision rather than
    // from today, so a claim files beside the work and not beside the signing.
    let month = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .expect("a month");
    assert_eq!(month.len(), 7, "a month directory: {month}");

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");
    assert!(report.ok(), "{:?}", report.findings().collect::<Vec<_>>());
    assert!(report.vouches_for(&head(&store)));
}

#[test]
fn two_roles_over_one_revision_are_two_names_and_neither_collides() {
    let directory = scratch("two-roles");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);

    let author = vouch(&store, head(&store), "author", &secret);
    let reviewer = vouch(&store, head(&store), "reviewer", &secret);

    assert_ne!(file_of(&store, &author), file_of(&store, &reviewer));
    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");
    assert!(report.ok(), "{:?}", report.findings().collect::<Vec<_>>());
    assert_eq!(report.held().len(), 2);
}

/// The second tier: two keys, one revision, one role. Neither may take the
/// plain name, or a file sync would see one file where there are two claims.
#[test]
fn two_keys_in_one_role_are_parted_by_the_key() {
    let directory = scratch("two-keys");
    let store = store_of(&directory, 1);
    let (mine, my_key) = keys(&directory);
    believe(&store, &my_key);

    let theirs = key::generate(&directory.join("other"), Some(PASSWORD.to_owned()))
        .expect("another key pair");
    let their_secret =
        key::load(&theirs.secret, Some(PASSWORD.to_owned())).expect("the other key back");

    let first = sign::claim_for(head(&store), "author".parse().unwrap(), &mine, &Platform)
        .expect("a claim");
    let second = sign::claim_for(
        head(&store),
        "author".parse().unwrap(),
        &their_secret,
        &Platform,
    )
    .expect("another claim");

    let held = [(first.digest(), first.clone())];
    let stem = naming::stem_for(
        &second.digest(),
        &second,
        store.documents().expect("documents"),
        held.iter().map(|(digest, claim)| (digest, claim)),
    );

    assert_ne!(stem, filed(&store, &first));
    assert!(
        stem.ends_with(&naming::key_prefix(&second.key)),
        "the key is what parts them: {stem}"
    );
}

/// The point of the whole decision: five lines in a text editor, one
/// `minisign -Sm`, and the claim counts.
#[test]
fn a_claim_written_by_hand_under_any_name_counts() {
    let directory = scratch("by-hand");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);

    let claim = sign::claim_for(
        head(&store),
        "reviewer".parse().unwrap(),
        &secret,
        &Platform,
    )
    .expect("a claim");
    let bytes = claim.render().into_bytes();

    // A name nobody computed, in the directory a person would put it in.
    let path = layout::claims(store.root()).join("my review.claim.txt");
    fs::create_dir_all(layout::claims(store.root())).expect("the directory");
    fs::write(&path, &bytes).expect("the claim");
    fs::write(
        layout::claims(store.root()).join("my review.claim.txt.minisig"),
        sign::signature(&secret, &bytes, "my review.claim.txt").expect("a signature"),
    )
    .expect("the signature");

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(
        report.ok(),
        "a hand-written claim is not a fault: {:?}",
        report.findings().collect::<Vec<_>>()
    );
    assert!(
        report.vouches_for(&head(&store)),
        "it counts for exactly what it says"
    );
    assert!(
        report
            .notes()
            .any(|finding| matches!(finding, Finding::Misfiled { .. })),
        "and it is told where it belongs"
    );
}

#[test]
fn one_claim_under_two_names_is_one_claim() {
    let directory = scratch("duplicate");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let claim = vouch(&store, head(&store), "author", &secret);

    // The same bytes again, somewhere else — what a copy that lacked the
    // revision would have produced before it received the history.
    let bytes = claim.render().into_bytes();
    let elsewhere = layout::claims(store.root()).join("a copy.claim.txt");
    fs::write(&elsewhere, &bytes).expect("a second copy");
    fs::write(
        layout::claims(store.root()).join("a copy.claim.txt.minisig"),
        sign::signature(&secret, &bytes, "a copy.claim.txt").expect("a signature"),
    )
    .expect("its signature");

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");

    assert!(report.ok(), "{:?}", report.findings().collect::<Vec<_>>());
    assert_eq!(report.held().len(), 1, "one claim, not two");
    assert!(
        report
            .notes()
            .any(|finding| matches!(finding, Finding::Duplicate { .. }))
    );
}

// ---------------------------------------------------------------------------
// Claims over one file — decision 0004
// ---------------------------------------------------------------------------

/// Record one more revision of the folder `store` lives in, after writing
/// `files` into it.
fn step(store: &mut Store, files: &[(&str, &str)], message: &str) -> RevisionId {
    let folder = store.root().parent().expect("the folder").to_path_buf();
    for (name, text) in files {
        fs::write(folder.join(name), text).expect("a file");
    }
    let working = Working::read(&folder, store.skipped()).expect("the folder");
    let recording = Recording {
        parents: store.history().heads().into_iter().collect(),
        author: "Adam Harris <adam@example.com>".to_owned(),
        when: Platform.now().expect("a clock"),
        message: message.to_owned(),
        moves: Vec::new(),
        at: Vec::new(),
        accepted: BTreeSet::new(),
        only: Restriction::Everything,
        kinds: Kinds::default(),
        extensions: BTreeMap::new(),
    };
    record(store, &working, &recording, &mut Platform).expect("a revision");
    head(store)
}

/// The file at `path` in the tree of `revision`.
fn file_at(store: &Store, revision: &RevisionId, path: &str) -> historica::core::FileId {
    let tree = store.tree(revision).expect("the tree");
    let [file] = tree.at(path)[..] else {
        panic!("one file at {path}");
    };
    file
}

/// A stand-in for the claimant's tool's content digest. This crate never
/// computes one, so the tests supply it the way a caller would.
fn content_of(text: &str) -> ContentDigest {
    format!("sha256:{}", historica::format::digest(text.as_bytes()))
        .parse()
        .expect("a content digest")
}

fn vouch_for_file(
    store: &Store,
    revision: RevisionId,
    file: historica::core::FileId,
    content: ContentDigest,
    role: &str,
    secret: &SecretKey,
) -> Claim {
    let claim = sign::file_claim_for(
        revision,
        file,
        content,
        role.parse::<Role>().expect("a role"),
        secret,
        &Platform,
    )
    .expect("a claim");
    let stem = filed(store, &claim);
    sign::write(store.filesystem(), store.root(), &claim, &stem, secret).expect("it written");
    claim
}

#[test]
fn a_claim_over_one_file_is_written_as_claim_1_and_read_back() {
    let directory = scratch("file-round-trip");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let revision = head(&store);
    let file = file_at(&store, &revision, "notes.txt");
    let claim = vouch_for_file(
        &store,
        revision,
        file,
        content_of("line 0\n"),
        "reviewer",
        &secret,
    );

    let written = fs::read_to_string(file_of(&store, &claim)).expect("the claim");
    assert!(written.starts_with("claim-1\n"), "{written}");
    assert_eq!(Claim::parse(&written).as_ref(), Ok(&claim));

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");
    assert!(report.ok(), "{:?}", report.findings().collect::<Vec<_>>());
    let [held] = report.held() else {
        panic!("one claim");
    };
    assert_eq!(held.claim, claim);
    assert_eq!(
        held.claim.scope,
        Scope::File {
            file,
            content: content_of("line 0\n")
        }
    );
    assert_eq!(
        held.file,
        verify::FileCheck::Found {
            path: "notes.txt".to_owned()
        }
    );
    assert!(held.counts());
    assert!(report.vouches_for_file(&file, &content_of("line 0\n")));
    assert!(
        !report.vouches_for_file(&file, &content_of("line 1\n")),
        "another content is not what was vouched for"
    );
    assert_eq!(report.vouched_files().count(), 1);
}

/// One file is not the revision, nor the history behind it, so `vouched`,
/// `vouches_for` and `complete` answer exactly as they would without it.
#[test]
fn a_claim_over_one_file_vouches_for_no_revision() {
    let directory = scratch("file-not-revision");
    let store = store_of(&directory, 3);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let revision = head(&store);
    let file = file_at(&store, &revision, "notes.txt");
    vouch_for_file(
        &store,
        revision,
        file,
        content_of("line 2\n"),
        "reviewer",
        &secret,
    );

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");
    assert!(report.ok());
    assert!(report.vouched().is_empty());
    assert!(!report.vouches_for(&revision));
    assert!(!report.complete());
    assert!(
        report
            .notes()
            .any(|finding| matches!(finding, Finding::Unvouched { revision: r } if *r == revision))
    );

    // A whole-revision claim beside it is what makes the store complete, and
    // the one-file claim changes nothing about that answer.
    vouch(&store, revision, "author", &secret);
    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");
    assert!(report.complete());
    assert_eq!(report.vouched().len(), 3);
    assert_eq!(report.vouched_files().count(), 1);
}

/// The point of naming the content: a later revision that leaves the file's
/// content alone does not unseat the claim, and one that changes it does —
/// judged by the caller, from the material the report hands back.
#[test]
fn a_claim_over_one_file_stands_while_its_content_does() {
    let directory = scratch("file-stands");
    let mut store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let first = head(&store);
    let file = file_at(&store, &first, "notes.txt");
    vouch_for_file(
        &store,
        first,
        file,
        content_of("line 0\n"),
        "reviewer",
        &secret,
    );

    // Another file changes; this one does not.
    let second = step(&mut store, &[("other.txt", "elsewhere\n")], "another file");
    assert_eq!(file_at(&store, &second, "notes.txt"), file);
    let now = fs::read_to_string(store.root().parent().unwrap().join("notes.txt")).unwrap();
    let report = verify::verify(&reopen(&store)).expect("a report");
    assert!(report.vouches_for_file(&file, &content_of(&now)));

    // Now it does.
    step(&mut store, &[("notes.txt", "rewritten\n")], "a rewrite");
    let now = fs::read_to_string(store.root().parent().unwrap().join("notes.txt")).unwrap();
    let report = verify::verify(&reopen(&store)).expect("a report");
    assert!(
        report.ok(),
        "the claim is still a true claim about its revision"
    );
    assert!(!report.vouches_for_file(&file, &content_of(&now)));
}

#[test]
fn a_claim_over_a_file_its_revision_does_not_hold_is_an_error() {
    let directory = scratch("file-missing");
    let mut store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let first = head(&store);
    // A real file, added after the revision the claim names.
    let second = step(&mut store, &[("later.txt", "later\n")], "later");
    let later = file_at(&store, &second, "later.txt");
    assert_eq!(
        verify::find_file(&store, &first, &later),
        verify::FileCheck::Missing
    );
    vouch_for_file(
        &store,
        first,
        later,
        content_of("later\n"),
        "reviewer",
        &secret,
    );

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");
    assert!(!report.ok());
    assert!(
        report.errors().any(|finding| matches!(
            finding,
            Finding::NoSuchFile { revision, file, .. } if *revision == first && *file == later
        )),
        "{:?}",
        report.findings().collect::<Vec<_>>()
    );
    let [held] = report.held() else {
        panic!("one claim");
    };
    assert!(held.verified, "the signature is good");
    assert_eq!(held.file, verify::FileCheck::Missing);
    assert!(!held.counts(), "and the claim counts for nothing");
    assert!(!report.vouches_for_file(&later, &content_of("later\n")));
}

#[test]
fn a_claim_over_one_file_by_an_unknown_key_is_a_note() {
    let directory = scratch("file-untrusted");
    let store = store_of(&directory, 1);
    let (secret, _) = keys(&directory);
    let revision = head(&store);
    let file = file_at(&store, &revision, "notes.txt");
    vouch_for_file(
        &store,
        revision,
        file,
        content_of("line 0\n"),
        "reviewer",
        &secret,
    );

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");
    assert!(report.ok());
    assert!(
        report
            .notes()
            .any(|finding| matches!(finding, Finding::Untrusted { .. }))
    );
    assert!(report.held()[0].verified);
    assert!(!report.held()[0].counts());
    assert_eq!(report.vouched_files().count(), 0);
}

/// Claims travel by file sync and history by `receive`, so a claim over a
/// file at a revision that has not arrived is ordinary — and unjudgeable, so
/// it does not count until the revision is here.
#[test]
fn a_claim_over_one_file_at_an_absent_revision_is_a_note_and_does_not_count() {
    let directory = scratch("file-absent");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let file = file_at(&store, &head(&store), "notes.txt");
    let elsewhere = historica::format::digest(b"a revision in somebody else's store");
    vouch_for_file(
        &store,
        elsewhere,
        file,
        content_of("line 0\n"),
        "reviewer",
        &secret,
    );

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");
    assert!(report.ok());
    assert!(
        report
            .notes()
            .any(|finding| matches!(finding, Finding::Absent { .. }))
    );
    assert_eq!(report.held()[0].file, verify::FileCheck::Unknown);
    assert!(!report.held()[0].counts());
}

/// A claim over one file is filed beside its revision with the file's ID
/// after the role, so one reviewer's claims over two files of one revision,
/// and a claim over the whole of it, take three plain names.
#[test]
fn claims_over_two_files_of_one_revision_are_two_names() {
    let directory = scratch("file-names");
    let mut store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let revision = step(&mut store, &[("other.txt", "elsewhere\n")], "another file");
    let notes = file_at(&store, &revision, "notes.txt");
    let other = file_at(&store, &revision, "other.txt");

    let one = vouch_for_file(
        &store,
        revision,
        notes,
        content_of("line 0\n"),
        "reviewer",
        &secret,
    );
    let two = vouch_for_file(
        &store,
        revision,
        other,
        content_of("elsewhere\n"),
        "reviewer",
        &secret,
    );
    let whole = vouch(&store, revision, "reviewer", &secret);

    let names: Vec<String> = [&one, &two, &whole]
        .iter()
        .map(|claim| filed(&store, claim))
        .collect();
    assert!(names[0].ends_with(&format!(
        " — reviewer {}",
        notes.abbreviate(naming::FILE_CHARS)
    )));
    assert!(names[1].ends_with(&format!(
        " — reviewer {}",
        other.abbreviate(naming::FILE_CHARS)
    )));
    assert!(names[2].ends_with(" — reviewer"));

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");
    assert!(report.ok());
    assert!(
        !report
            .notes()
            .any(|finding| matches!(finding, Finding::Misfiled { .. })),
        "{:?}",
        report.findings().collect::<Vec<_>>()
    );
    assert_eq!(report.held().len(), 3);
    assert_eq!(report.vouched_files().count(), 2);
}

/// The signature covers the file and content lines as it covers every other,
/// so a claim edited to vouch for other content is refused.
#[test]
fn a_claim_1_with_a_bad_signature_is_refused() {
    let directory = scratch("file-refused");
    let store = store_of(&directory, 1);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let revision = head(&store);
    let file = file_at(&store, &revision, "notes.txt");
    let claim = vouch_for_file(
        &store,
        revision,
        file,
        content_of("line 0\n"),
        "reviewer",
        &secret,
    );

    // Change what the claim says the content was, under its own name: the
    // signature covers the content line as it covers every other.
    let path = file_of(&store, &claim);
    let text = fs::read_to_string(&path).expect("the claim");
    fs::write(
        &path,
        text.replace(
            &format!("content {}", content_of("line 0\n")),
            &format!("content {}", content_of("forged\n")),
        ),
    )
    .expect("the edit");

    let store = reopen(&store);
    let report = verify::verify(&store).expect("a report");
    assert!(
        report
            .errors()
            .any(|finding| matches!(finding, Finding::Refused { .. }))
    );
    assert!(!report.vouches_for_file(&file, &content_of("forged\n")));
}

/// Decision 0004 changes nothing a store already holds: a whole-revision
/// claim is still written as the same five lines of `claim-0`, so it is the
/// same file it would have been before, and a reader that predates 0004 reads
/// it.
#[test]
fn a_whole_revision_claim_is_still_written_as_claim_0() {
    let directory = scratch("still-claim-0");
    let store = store_of(&directory, 1);
    let (secret, _) = keys(&directory);
    let claim = vouch(&store, head(&store), "author", &secret);

    let written = fs::read_to_string(file_of(&store, &claim)).expect("the claim");
    assert_eq!(written.lines().count(), 5);
    assert!(written.starts_with("claim-0\nrevision "), "{written}");
    assert_eq!(claim.scope, Scope::Revision);
    assert!(!filed(&store, &claim).ends_with(' '));
}

/// Decision 0006: a `claim-2` vouches for one document that is not a
/// revision, by its digest, and for nothing behind it.
#[test]
fn a_claim_over_one_document_vouches_for_that_document_alone() {
    let directory = scratch("document");
    let store = store_of(&directory, 2);
    let (secret, key) = keys(&directory);
    believe(&store, &key);
    let revision = store.get(&head(&store)).expect("read").expect("held");
    let document = *revision.edited.values().next().expect("an edited file");
    let author = "author".parse::<Role>().expect("a role");
    let claim =
        sign::document_claim_for(document, author.clone(), &secret, &Platform).expect("a claim");
    assert_eq!(claim.scope, Scope::Document);
    sign::write(
        store.filesystem(),
        store.root(),
        &claim,
        &filed(&store, &claim),
        &secret,
    )
    .expect("written");

    let report = verify::verify(&reopen(&store)).expect("a report");
    assert!(report.ok(), "{:?}", report.findings().collect::<Vec<_>>());
    let held = &report.held()[0];
    assert_eq!(held.claim, claim);
    assert!(held.counts());
    assert!(
        !report
            .notes()
            .any(|finding| matches!(finding, Finding::Absent { .. })),
        "the store holds the document"
    );
    assert!(
        report.vouched().is_empty(),
        "a document is no revision, and vouches for none"
    );

    // Over a document this store does not hold, it is noted as absent.
    let elsewhere = sign::document_claim_for(
        historica::format::digest(b"somewhere else"),
        author,
        &secret,
        &Platform,
    )
    .expect("a claim");
    sign::write(
        store.filesystem(),
        store.root(),
        &elsewhere,
        &filed(&store, &elsewhere),
        &secret,
    )
    .expect("written");
    let report = verify::verify(&reopen(&store)).expect("a report");
    assert!(
        report
            .notes()
            .any(|finding| matches!(finding, Finding::Absent { .. }))
    );
}
