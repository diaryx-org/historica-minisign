//! Reading what a store's claims say, and judging it.
//!
//! Historica's decision 0046: `verify` reads and never writes, and reports in
//! decision 0006's split — **errors** mean the store holds something that is
//! wrong, **notes** are observations about a store that is intact. A store with
//! no claims at all verifies vacuously, "because a tool that failed every store
//! it had not yet met would teach people not to run it".
//!
//! # What coverage means
//!
//! A claim vouches for a digest; a revision's digest pins its bytes, which pin
//! its parents' digests, and so on to the roots. So one claim over one revision
//! covers the whole ancestry behind it, and signing every revision is a choice
//! rather than a requirement.
//!
//! That is why an uncovered *head* is what gets a note. Every revision is an
//! ancestor of some head, so heads are where the question is actually decided:
//! cover every head and you have covered everything. Naming each uncovered
//! revision instead would print a thousand notes that all say the one thing.
//!
//! # What a name can say, and what it cannot
//!
//! Decision 0003: a claim is identified by parsing it, never by reading its
//! filename, so a claim under any name at all is read and counted. What the
//! name buys is a folder worth opening, and the check that buys it back is
//! [`Finding::Misfiled`] — a note, because the store is intact and the claim
//! counts in full. A readable name can mislead a reader in a way a digest could
//! not, and a design that makes a directory worth reading owes the reader a
//! check that what they read is true.
//!
//! [`Finding::NameIsFalse`] survives for the one name that still asserts
//! something checkable: sixty-four hex characters, which is either a store
//! written before 0003 or the last-resort tier, and either way a false one is
//! still false.
//!
//! # What a claim cannot say, and this cannot check
//!
//! A signature never stops being valid, so a store can present a subset of a
//! history — every document intact, every claim verifying — and the subset lies
//! by omission. 0046's answer to the half of that which is answerable offline
//! is head statements, which are specified there and not built here. Nothing in
//! this module detects a withheld revision, and it does not pretend to.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use historica::core::RevisionId;
use historica::format::digest;
use historica::fs::{Filesystem, Kind, read_to_string};
use historica::store::{Store, platform_name};
use minisign_verify::Signature;

use crate::claim::{Claim, ClaimError, Key};
use crate::layout::{
    CLAIM_SUFFIX, claims as claims_dir, digest_of_name, is_claim_name, signed_name,
};
use crate::naming;
use crate::trust::Trust;

/// Whether a finding means the store is wrong, or only that something is worth
/// saying about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The store holds something wrong.
    Error,
    /// An observation about a store that is intact.
    Note,
}

/// One thing `verify` has to say.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Finding {
    /// A claim whose bytes do not parse.
    Malformed {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        because: ClaimError,
    },
    /// A claim whose filename is a digest, and not the digest of its own bytes.
    NameIsFalse {
        /// The file.
        path: PathBuf,
        /// What its name says.
        claimed: RevisionId,
        /// What its bytes hash to.
        actual: RevisionId,
    },
    /// A claim that is not filed under the name this scheme would choose.
    Misfiled {
        /// Where it is.
        path: PathBuf,
        /// Where it belongs, relative to `claims/`.
        should_be: String,
    },
    /// A second file holding a claim another file already holds.
    Duplicate {
        /// The copy not being counted.
        path: PathBuf,
        /// The copy that is.
        of: PathBuf,
    },
    /// A claim with no signature beside it.
    Unsigned {
        /// The claim.
        path: PathBuf,
    },
    /// A signature with no claim beside it.
    Orphaned {
        /// The signature.
        path: PathBuf,
    },
    /// A signature that does not verify under the key the claim names.
    Refused {
        /// The claim.
        path: PathBuf,
        /// The key it names.
        key: Key,
        /// What minisign said.
        because: String,
    },
    /// A file in `trust/` that is not an entry.
    MalformedTrust {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        because: crate::trust::EntryError,
    },
    /// A claim by a key the policy does not hold.
    Untrusted {
        /// The claim.
        path: PathBuf,
        /// The key that signed it.
        key: Key,
    },
    /// A claim naming a revision this store does not have.
    Absent {
        /// The claim.
        path: PathBuf,
        /// What it vouches for.
        revision: RevisionId,
    },
    /// A head no trusted key vouches for.
    Unvouched {
        /// The head.
        revision: RevisionId,
    },
    /// A file in `claims/` that is neither a claim nor a signature.
    Foreign {
        /// The file.
        path: PathBuf,
    },
}

impl Finding {
    /// Which of decision 0006's two buckets this falls in.
    ///
    /// The one that took an argument is [`Finding::Unsigned`]. A claim on its
    /// own asserts something and backs it with nothing, and a reader who reads
    /// the claim without noticing the absent signature believes it — which is
    /// the cheapest possible attack on this design, costing an attacker one
    /// text file. Making it an error is what stops the absence being quiet.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Malformed { .. }
            | Self::NameIsFalse { .. }
            | Self::Unsigned { .. }
            | Self::Orphaned { .. }
            | Self::Refused { .. }
            | Self::MalformedTrust { .. } => Severity::Error,
            Self::Untrusted { .. }
            | Self::Absent { .. }
            | Self::Unvouched { .. }
            | Self::Misfiled { .. }
            | Self::Duplicate { .. }
            | Self::Foreign { .. } => Severity::Note,
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { path, because } => {
                write!(f, "{} is not a claim: {because}", path.display())
            }
            Self::NameIsFalse {
                path,
                claimed,
                actual,
            } => write!(
                f,
                "{} claims {claimed} and hashes to {actual}; the name is a \
                 claim and it is false",
                path.display()
            ),
            Self::Misfiled { path, should_be } => write!(
                f,
                "{} belongs at {should_be}; the claim counts either way, and \
                 `historica-minisign arrange` moves it",
                path.display()
            ),
            Self::Duplicate { path, of } => write!(
                f,
                "{} holds the same claim as {}, and is counted once; \
                 `historica-minisign arrange` reduces them to one",
                path.display(),
                of.display()
            ),
            Self::Unsigned { path } => write!(
                f,
                "{} has no signature beside it; a claim with nothing backing \
                 it vouches for nothing, and is read by anyone who does not \
                 notice",
                path.display()
            ),
            Self::Orphaned { path } => {
                write!(f, "{} signs a claim that is not here", path.display())
            }
            Self::Refused { path, key, because } => write!(
                f,
                "{} does not verify under {key}: {because}",
                path.display()
            ),
            Self::MalformedTrust { path, because } => {
                write!(f, "{} is not a trust entry: {because}", path.display())
            }
            Self::Untrusted { path, key } => write!(
                f,
                "{} is signed by {key}, which nothing in trust/ speaks for",
                path.display()
            ),
            Self::Absent { path, revision } => write!(
                f,
                "{} vouches for {revision}, which this store does not hold",
                path.display()
            ),
            Self::Unvouched { revision } => write!(
                f,
                "no trusted key vouches for the head {revision}, nor for \
                 anything descended from it"
            ),
            Self::Foreign { path } => write!(
                f,
                "{} is in claims/ and is neither a claim nor a signature",
                path.display()
            ),
        }
    }
}

/// One claim the store holds, and what became of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// Where it is.
    pub path: PathBuf,
    /// What it says.
    pub claim: Claim,
    /// Whether its signature verified under the key it names.
    pub verified: bool,
    /// Who the policy takes that key to speak for, if it holds it.
    pub who: Option<String>,
}

impl Held {
    /// Whether this claim counts: signed by a key this copy believes.
    pub fn counts(&self) -> bool {
        self.verified && self.who.is_some()
    }
}

/// What `verify` found.
#[derive(Debug, Clone, Default)]
pub struct Report {
    findings: Vec<Finding>,
    held: Vec<Held>,
    vouched: BTreeSet<RevisionId>,
    revisions: usize,
}

impl Report {
    /// Everything found, errors before notes, each group in the order it was
    /// found.
    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        let errors = self
            .findings
            .iter()
            .filter(|finding| finding.severity() == Severity::Error);
        let notes = self
            .findings
            .iter()
            .filter(|finding| finding.severity() == Severity::Note);
        errors.chain(notes)
    }

    /// Findings that mean the store holds something wrong.
    pub fn errors(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.severity() == Severity::Error)
    }

    /// Observations about a store that is intact.
    pub fn notes(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.severity() == Severity::Note)
    }

    /// Every claim read, in the order the directory gave them up.
    pub fn held(&self) -> &[Held] {
        &self.held
    }

    /// Every revision a trusted key vouches for, ancestry included.
    pub fn vouched(&self) -> &BTreeSet<RevisionId> {
        &self.vouched
    }

    /// How many revisions the store holds.
    pub fn revisions(&self) -> usize {
        self.revisions
    }

    /// Whether a trusted key vouches for this revision.
    pub fn vouches_for(&self, revision: &RevisionId) -> bool {
        self.vouched.contains(revision)
    }

    /// Whether nothing is wrong. Notes do not affect this.
    pub fn ok(&self) -> bool {
        self.errors().next().is_none()
    }

    /// Whether nothing is wrong *and* every head is vouched for — the form the
    /// check takes in somebody's CI.
    pub fn complete(&self) -> bool {
        self.ok()
            && !self
                .findings
                .iter()
                .any(|finding| matches!(finding, Finding::Unvouched { .. }))
    }
}

/// Read a store's claims and its policy, and say what they amount to.
///
/// Reads; writes nothing, ever.
pub fn verify<F: Filesystem>(store: &Store<F>) -> io::Result<Report> {
    let files = store.filesystem();
    let root = store.root();

    let mut report = Report {
        revisions: store.len(),
        ..Report::default()
    };

    let policy = Trust::read(files, root)?;
    for (path, because) in policy.malformed() {
        report.findings.push(Finding::MalformedTrust {
            path: path.to_path_buf(),
            because: because.clone(),
        });
    }

    let (found, signatures, foreign) = look(files, &claims_dir(root))?;
    report
        .findings
        .extend(foreign.into_iter().map(|path| Finding::Foreign { path }));
    let names: BTreeSet<String> = found.iter().map(|(name, _)| name.clone()).collect();

    // Pass one: the bytes, and what they are. Decision 0003: a claim is
    // identified by parsing it, so nothing here consults a filename except to
    // check the one kind of name that still asserts something checkable.
    let mut read: Vec<(String, PathBuf, Vec<u8>, RevisionId, Claim)> = Vec::new();
    for (name, path) in found {
        let bytes = files.read(&path)?;
        let actual = digest(&bytes);

        // Sixty-four hex characters is a specific assertion about the bytes
        // under it, and a false one is wrong whatever the file says inside — so
        // it is checked before the parse, and the parse is not reported. Every
        // other name asserts nothing this can refute here.
        if let Some(claimed) = last(&name).and_then(digest_of_name)
            && claimed != actual
        {
            report.findings.push(Finding::NameIsFalse {
                path,
                claimed,
                actual,
            });
            continue;
        }

        let text = match String::from_utf8(bytes.clone()) {
            Ok(text) => text,
            Err(_) => {
                report.findings.push(Finding::Malformed {
                    path,
                    because: ClaimError::Preamble {
                        found: "bytes that are not text".to_owned(),
                    },
                });
                continue;
            }
        };
        match Claim::parse(&text) {
            Ok(claim) => read.push((name, path, bytes, actual, claim)),
            Err(because) => report.findings.push(Finding::Malformed { path, because }),
        }
    }

    // The names this scheme would have chosen, which needs every claim in hand
    // and the revisions they name. A store whose documents will not parse is
    // `historica check`'s to report rather than this tool's: here it costs the
    // name check alone, and every claim is still read and still counted.
    let parsed: Vec<(&RevisionId, &Claim)> = read
        .iter()
        .map(|(_, _, _, id, claim)| (id, claim))
        .collect();
    let stems = match store.documents() {
        Ok(documents) => naming::stems(parsed, documents),
        Err(_) => BTreeMap::new(),
    };

    // Pass two: what each claim amounts to. Deduplicated on the digest computed
    // above and never on the name, so one claim under two names is one claim.
    let mut seen: BTreeMap<RevisionId, PathBuf> = BTreeMap::new();
    for (name, path, bytes, id, claim) in read {
        if let Some(first) = seen.get(&id) {
            report.findings.push(Finding::Duplicate {
                path,
                of: first.clone(),
            });
            continue;
        }
        seen.insert(id, path.clone());

        if let Some(stem) = stems.get(&id) {
            let should_be = format!("{stem}{CLAIM_SUFFIX}");
            if name != should_be {
                report.findings.push(Finding::Misfiled {
                    path: path.clone(),
                    should_be,
                });
            }
        }

        let verified = match signatures.get(name.as_str()) {
            None => {
                report
                    .findings
                    .push(Finding::Unsigned { path: path.clone() });
                false
            }
            Some(signature) => match check(files, signature, &bytes, &claim.key) {
                Ok(()) => true,
                Err(because) => {
                    report.findings.push(Finding::Refused {
                        path: path.clone(),
                        key: claim.key.clone(),
                        because,
                    });
                    false
                }
            },
        };

        let who = policy.who(&claim.key).map(str::to_owned);
        if who.is_none() {
            report.findings.push(Finding::Untrusted {
                path: path.clone(),
                key: claim.key.clone(),
            });
        }

        let present = store.holds(&claim.revision);
        if !present {
            report.findings.push(Finding::Absent {
                path: path.clone(),
                revision: claim.revision,
            });
        }

        let held = Held {
            path,
            claim,
            verified,
            who,
        };
        if held.counts() && present {
            // Ancestry, not the revision alone: a digest pins its bytes, which
            // pin its parents' digests, so vouching for a revision vouches for
            // everything behind it.
            match store.reachable(&held.claim.revision) {
                Ok(behind) => report.vouched.extend(behind.into_iter().map(|(id, _)| id)),
                // The store holds the revision — `present` — so the only way
                // the walk fails is a parent it does not hold, which is
                // `historica check`'s finding rather than this tool's. Vouch
                // for what was named and say nothing further.
                Err(_) => {
                    report.vouched.insert(held.claim.revision);
                }
            }
        }
        report.held.push(held);
    }

    for (name, path) in signatures {
        if !names.contains(&name) {
            report.findings.push(Finding::Orphaned { path });
        }
    }

    for head in current_heads(store) {
        if !report.vouched.contains(&head) {
            report.findings.push(Finding::Unvouched { revision: head });
        }
    }

    Ok(report)
}

/// The heads a person is standing on: the ones nothing has rewritten.
///
/// Historica's decision 0023's rule, because a note about an uncovered head
/// should name a head somebody could actually sign. An amended revision is
/// still a head by parent edges — its successor took its parents rather than it
/// — so without this a store with one amendment in it would carry an unvouched
/// note forever, naming a revision nobody works on.
///
/// Where filtering leaves nothing, every head is returned: a store holding a
/// revision whose successor has not arrived is described as it is.
pub fn current_heads<F: Filesystem>(store: &Store<F>) -> BTreeSet<RevisionId> {
    let history = store.history();
    let heads = history.heads();
    let superseded = history.superseded();
    let current: BTreeSet<RevisionId> = heads.difference(&superseded).copied().collect();
    if current.is_empty() { heads } else { current }
}

/// The claims, the signatures by the claim each names, and whatever else was in
/// the directory.
///
/// A claim is keyed by its path relative to `claims/`, so a signature pairs
/// with the claim beside it rather than with any file of the same basename
/// filed under another month.
type Looked = (
    Vec<(String, PathBuf)>,
    BTreeMap<String, PathBuf>,
    Vec<PathBuf>,
);

fn look<F: Filesystem + ?Sized>(files: &F, directory: &Path) -> io::Result<Looked> {
    let mut looked: Looked = Default::default();
    walk(files, directory, "", &mut looked)?;
    looked.0.sort();
    Ok(looked)
}

/// One directory under `claims/`, and everything below it.
///
/// Recursive because decision 0041's month directory arrives inside the stem,
/// and a reader that stopped at the top level would find nothing at all in a
/// store written under decision 0003.
fn walk<F: Filesystem + ?Sized>(
    files: &F,
    directory: &Path,
    prefix: &str,
    looked: &mut Looked,
) -> io::Result<()> {
    let entries = match files.entries(directory) {
        Ok(entries) => entries,
        // No claims directory is a store nobody has vouched for, which is a
        // store this tool has nothing to say about rather than a fault.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    for entry in entries {
        let Some(name) = entry.path.file_name().and_then(|name| name.to_str()) else {
            looked.2.push(entry.path);
            continue;
        };
        // Historica's own list of names a store cannot own — the ones a file
        // browser or a sync program writes into every directory it touches,
        // unprompted. Reporting those as foreign would be reporting the
        // operating system.
        if platform_name(name) {
            continue;
        }
        let relative = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };

        match files.look(&entry.path)? {
            Some(Kind::Directory) => walk(files, &entry.path, &relative, looked)?,
            Some(Kind::File) => {
                if let Some(signed) = signed_name(&relative) {
                    looked.1.insert(signed.to_owned(), entry.path);
                } else if is_claim_name(&relative) {
                    looked.0.push((relative, entry.path));
                } else {
                    looked.2.push(entry.path);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// The last component of a path relative to `claims/`.
fn last(relative: &str) -> Option<&str> {
    relative.rsplit('/').next()
}

/// Check one detached signature over some bytes, under the key that should
/// have made it.
///
/// The whole of this crate's cryptography, as one function, so that a caller
/// holding a claim and a signature — a test, or one day a `receive` that
/// refuses history nobody vouches for — checks them through the same door
/// `verify` does rather than through a second opinion.
///
/// `signature` is the text of a `.minisig` file.
pub fn check_signature(bytes: &[u8], signature: &str, key: &Key) -> Result<(), String> {
    let signature = Signature::decode(signature).map_err(|error| error.to_string())?;
    let key = key.public_key().map_err(|error| error.to_string())?;
    // Legacy signatures are accepted because `minisign -Vm` accepts them: a
    // claim signed years ago by an older minisign is a claim, and decision
    // 0001 requires this tool to take what the command takes. The mode signs
    // the message rather than a hash of it, which for a five-line document is
    // the same Ed25519 either way.
    key.verify(bytes, &signature, true)
        .map_err(|error| error.to_string())
}

/// The same, for a signature that is still a file.
fn check<F: Filesystem + ?Sized>(
    files: &F,
    signature: &Path,
    bytes: &[u8],
    key: &Key,
) -> Result<(), String> {
    let text = read_to_string(files, signature).map_err(|error| error.to_string())?;
    check_signature(bytes, &text, key)
}
