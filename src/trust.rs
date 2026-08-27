//! The trust policy: whose word this copy accepts.
//!
//! ```text
//! trust-0
//! key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
//! who Adam Harris <adam@example.com>
//! ```
//!
//! One key to a file under `history/trust/`, on Historica's decision 0045's
//! container: the filename is a label for whoever opens the folder, and the
//! content is the fact. Entries are written with `create_new`, so two additions
//! on one machine cannot lose one; removing an entry is deleting its file.
//!
//! **Nothing here ever travels.** Decision 0046 argues that at length and this
//! module does not revisit it, but the shape of the argument is worth having
//! beside the code: a trust entry arriving from another store is authority
//! flowing from the party the policy exists to judge. A skip rule that arrives
//! means *record less*, which fails closed; a trust entry that arrives means
//! *believe more*. And union without tombstones structurally cannot make
//! removal win, which is the one thing revoking a key requires. So no operation
//! of this tool, and no operation of Historica, writes this directory from
//! another store.
//!
//! `who` is free text and this tool never matches on it. It is a label for a
//! person, not an identity — pretending otherwise would invite somebody to
//! trust the string instead of the key.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use historica::fs::{Filesystem, Kind, read_to_string};

use crate::claim::Key;
use crate::layout::{TRUST_SUFFIX, trust as trust_dir};

/// The preamble every trust entry begins with.
pub const PREAMBLE: &str = "trust-0";

/// What the tool writes when it first makes the directory: the grammar,
/// explained where the files are, stating no rule at all.
///
/// Historica's decision 0027 has a default explain itself and state nothing,
/// and 0045 inherits it. So does this: a file of nothing but comments is a
/// comment-only file in every reader, with no special case anywhere.
pub const EXPLANATION: &str = "\
# This directory is whose word this copy of the store accepts. One key to a
# file; the filename is a label for you, and nothing reads it. A file looks
# like this, with no `#` in front:
#
# trust-0
# key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
# who Adam Harris <adam@example.com>
#
# Nothing ever writes this directory from another store: receiving a store
# receives its history and its claims, never its opinion of who to believe.
# Adding a key is `historica-minisign trust add`, or writing a file like the
# above. Removing one is deleting its file.
";

/// The name the explanation is written under.
const EXPLANATION_FILE: &str = "how-this-works.txt";

/// One key, and the person this copy takes it to speak for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The key.
    pub key: Key,
    /// Who it speaks for, as free text.
    pub who: String,
}

impl Entry {
    /// The entry, as the bytes of its file.
    pub fn render(&self) -> String {
        format!("{PREAMBLE}\nkey {}\nwho {}\n", self.key, self.who)
    }

    /// Read one entry, or say that this file states nothing.
    ///
    /// `Ok(None)` is a file of comments and blank lines — the explanation this
    /// tool writes, or one somebody commented out — which is a file stating
    /// nothing rather than a file that is wrong.
    pub fn parse(text: &str) -> Result<Option<Self>, EntryError> {
        let mut lines = text
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim_start().starts_with('#') && !line.trim().is_empty());

        let Some((index, preamble)) = lines.next() else {
            return Ok(None);
        };
        if preamble != PREAMBLE {
            return Err(EntryError::Preamble {
                at: index + 1,
                found: preamble.to_owned(),
            });
        }

        let mut key = None;
        let mut who = None;
        for (index, line) in lines {
            let at = index + 1;
            let (header, value) = line.split_once(' ').unwrap_or((line, ""));
            let slot = match header {
                "key" => {
                    let parsed = value
                        .parse::<Key>()
                        .map_err(|error| EntryError::Malformed {
                            at,
                            header: "key",
                            because: error.to_string(),
                        })?;
                    key.replace(parsed).map(|_| "key")
                }
                "who" => {
                    if value.is_empty() {
                        return Err(EntryError::Malformed {
                            at,
                            header: "who",
                            because: "it says nobody".to_owned(),
                        });
                    }
                    who.replace(value.to_owned()).map(|_| "who")
                }
                other => {
                    return Err(EntryError::Unknown {
                        at,
                        found: other.to_owned(),
                    });
                }
            };
            if let Some(header) = slot {
                return Err(EntryError::Repeated { at, header });
            }
        }

        match (key, who) {
            (Some(key), Some(who)) => Ok(Some(Self { key, who })),
            (None, _) => Err(EntryError::Missing { header: "key" }),
            (_, None) => Err(EntryError::Missing { header: "who" }),
        }
    }
}

/// Every key this copy accepts, and every file in the directory that is not one.
#[derive(Debug, Clone, Default)]
pub struct Trust {
    entries: BTreeMap<String, Entry>,
    malformed: Vec<(PathBuf, EntryError)>,
}

impl Trust {
    /// Read the policy, keeping what is wrong with it rather than stopping at
    /// the first fault.
    ///
    /// A directory that is not there is a policy that holds nothing, which is
    /// what an unconfigured copy has and is not an error: a tool that failed
    /// every store it had not yet met would teach people not to run it.
    pub fn read<F: Filesystem + ?Sized>(files: &F, root: &Path) -> io::Result<Self> {
        let directory = trust_dir(root);
        let mut policy = Self::default();
        let entries = match files.entries(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(policy),
            Err(error) => return Err(error),
        };

        for entry in entries {
            if !matches!(files.look(&entry.path)?, Some(Kind::File)) {
                continue;
            }
            let Some(label) = label_of(&entry.path) else {
                continue;
            };
            let text = read_to_string(files, &entry.path)?;
            match Entry::parse(&text) {
                Ok(Some(held)) => {
                    policy.entries.insert(label, held);
                }
                Ok(None) => {}
                Err(error) => policy.malformed.push((entry.path, error)),
            }
        }
        Ok(policy)
    }

    /// The person this policy takes a key to speak for, if it holds it.
    pub fn who(&self, key: &Key) -> Option<&str> {
        self.entries
            .values()
            .find(|entry| &entry.key == key)
            .map(|entry| entry.who.as_str())
    }

    /// Whether this policy holds a key.
    pub fn holds(&self, key: &Key) -> bool {
        self.who(key).is_some()
    }

    /// Every entry, by the label its file is named with.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &Entry)> {
        self.entries
            .iter()
            .map(|(label, entry)| (label.as_str(), entry))
    }

    /// Whether this copy has stated any policy at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Files in the directory that are not entries, and why.
    pub fn malformed(&self) -> impl Iterator<Item = (&Path, &EntryError)> {
        self.malformed
            .iter()
            .map(|(path, error)| (path.as_path(), error))
    }
}

/// The longest a label this tool chooses for itself may be.
///
/// Historica's decision 0006 cuts a summary at sixty characters so that a name
/// has room for a date and an extension inside the 255 bytes every filesystem
/// in use allows, even where it is entirely non-ASCII. A label carries neither,
/// so sixty is already more than a person's name needs.
const LABEL_CHARS: usize = 60;

/// The label a key gets when nobody chose one: who it speaks for.
///
/// Decisions 0001 and 0046 both say the filename here is a label for whoever
/// opens the folder and that nothing reads it — so it should be the one thing
/// the person opening the folder wants to know, which is whose key it is. A
/// digest satisfied the letter of "nothing reads it" and none of the point.
///
/// `who` is free text, so what comes back is scrubbed rather than trusted: the
/// part before any `<`, with path separators and control characters turned to
/// spaces, runs of spaces collapsed, and leading dots removed. Where nothing
/// usable survives — a `who` of punctuation, or one that lands on the name the
/// explanation file already has — the answer is the digest of the key's text,
/// which is a filename whatever the key and the person are called.
///
/// Nothing about this has to agree with any other copy. `trust/` never crosses
/// a store boundary, which is 0046 at length, so unlike [`crate::naming`] there
/// is no replica to compute the same name and no `arrange` to reconcile one.
///
/// A label the tool chose is still only a label: renaming the file changes
/// nothing, and two keys for one person are told apart by whatever the caller
/// appends.
pub fn default_label(key: &Key, who: &str) -> String {
    let named = who.split('<').next().unwrap_or(who).trim();
    let candidate = if named.is_empty() {
        who.trim_matches(['<', '>']).trim()
    } else {
        named
    };

    let mut label = String::new();
    let mut pending = false;
    for character in candidate.chars().take(LABEL_CHARS) {
        let character = match character {
            character if character.is_control() => ' ',
            '/' | '\\' | ':' => ' ',
            character => character,
        };
        if character == ' ' {
            // A run of spaces is one space, and a leading one is none: a name
            // is being made, not transcribed.
            pending = !label.is_empty();
            continue;
        }
        if pending {
            label.push(' ');
            pending = false;
        }
        label.push(character);
    }
    // A leading dot hides the file on every Unix, and a trailing dot or space
    // is a name Windows will not keep as written. Both are trimmed together
    // rather than in turn, or a `who` of `../../etc/passwd` scrubs to a space
    // in front of the dots and keeps them.
    let label = label.trim_matches(|character| character == '.' || character == ' ');

    let explanation = EXPLANATION_FILE
        .strip_suffix(TRUST_SUFFIX)
        .unwrap_or(EXPLANATION_FILE);
    if label.is_empty() || !is_a_label(label) || label == explanation {
        return historica::format::digest(key.as_str().as_bytes()).abbreviate(12);
    }
    label.to_owned()
}

/// Whether a label is one filename.
///
/// The rule is deliberately about what a filesystem will take rather than about
/// what looks tidy: `..` and a path separator are the two spellings that would
/// have this tool write outside the directory it means to.
pub fn is_a_label(label: &str) -> bool {
    !label.is_empty()
        && label != "."
        && label != ".."
        && !label.contains(['/', '\\'])
        && !label.contains('\0')
}

/// Add one key to the policy, under `label`.
///
/// Written with `create_new`: a label already taken is refused rather than
/// overwritten, which is what stops two additions on one machine from losing
/// one. The directory and its explanation are made if they are not there.
///
/// Returns where the entry was written.
pub fn add<F: Filesystem + ?Sized>(
    files: &F,
    root: &Path,
    label: &str,
    entry: &Entry,
) -> Result<PathBuf, TrustError> {
    let directory = trust_dir(root);
    files
        .create_directory(&directory)
        .map_err(|error| TrustError::io(&directory, error))?;

    let explanation = directory.join(EXPLANATION_FILE);
    match files.create_new(&explanation, EXPLANATION.as_bytes()) {
        Ok(()) => {}
        // Already there, which is the ordinary case after the first add.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(TrustError::io(&explanation, error)),
    }

    if !is_a_label(label) {
        return Err(TrustError::NotALabel {
            label: label.to_owned(),
        });
    }

    let path = directory.join(format!("{label}{TRUST_SUFFIX}"));
    match files.create_new(&path, entry.render().as_bytes()) {
        Ok(()) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(TrustError::Taken {
            label: label.to_owned(),
            path,
        }),
        Err(error) => Err(TrustError::io(&path, error)),
    }
}

/// Remove one key from the policy, by the label its file is named with.
pub fn remove<F: Filesystem + ?Sized>(
    files: &F,
    root: &Path,
    label: &str,
) -> Result<PathBuf, TrustError> {
    let path = trust_dir(root).join(format!("{label}{TRUST_SUFFIX}"));
    match files.remove_file(&path) {
        Ok(()) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(TrustError::NoSuchLabel {
            label: label.to_owned(),
        }),
        Err(error) => Err(TrustError::io(&path, error)),
    }
}

/// The label a trust file's name states.
fn label_of(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    Some(name.strip_suffix(TRUST_SUFFIX).unwrap_or(name).to_owned())
}

/// Why a trust entry could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryError {
    /// The first line that says anything was not [`PREAMBLE`].
    Preamble {
        /// Which line.
        at: usize,
        /// What it said.
        found: String,
    },
    /// A header this grammar does not name.
    Unknown {
        /// Which line.
        at: usize,
        /// What it called itself.
        found: String,
    },
    /// A header stated twice.
    Repeated {
        /// Which line.
        at: usize,
        /// Which header.
        header: &'static str,
    },
    /// A header whose value is not what that header holds.
    Malformed {
        /// Which line.
        at: usize,
        /// Which header.
        header: &'static str,
        /// What is wrong with it.
        because: String,
    },
    /// A header this grammar requires is not there.
    Missing {
        /// Which one.
        header: &'static str,
    },
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preamble { at, found } => write!(
                f,
                "line {at} says `{found}`; a trust entry begins `{PREAMBLE}`"
            ),
            Self::Unknown { at, found } => write!(
                f,
                "line {at} states `{found}`, which a trust entry does not name"
            ),
            Self::Repeated { at, header } => {
                write!(f, "line {at} states `{header}` a second time")
            }
            Self::Malformed {
                at,
                header,
                because,
            } => write!(f, "line {at}'s `{header}` is wrong: {because}"),
            Self::Missing { header } => write!(f, "it states no `{header}`"),
        }
    }
}

impl std::error::Error for EntryError {}

/// Why the policy could not be written.
#[derive(Debug)]
#[non_exhaustive]
pub enum TrustError {
    /// A label another entry already holds.
    Taken {
        /// The label.
        label: String,
        /// The file already under it.
        path: PathBuf,
    },
    /// Something that is not one filename.
    NotALabel {
        /// What was offered.
        label: String,
    },
    /// A label no entry holds.
    NoSuchLabel {
        /// The label.
        label: String,
    },
    /// The filesystem refused.
    Io {
        /// What was being read or written.
        path: PathBuf,
        /// What it said.
        error: io::Error,
    },
}

impl TrustError {
    fn io(path: &Path, error: io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            error,
        }
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Taken { label, path } => write!(
                f,
                "`{label}` is already a label here, at {}; a key is added \
                 rather than replaced, so that two additions cannot lose one",
                path.display()
            ),
            Self::NotALabel { label } => write!(
                f,
                "`{label}` is not one filename, and a label is: it holds no \
                 `/`, and is not empty, `.`, or `..`"
            ),
            Self::NoSuchLabel { label } => {
                write!(f, "no key here is labelled `{label}`")
            }
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for TrustError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

    fn entry() -> Entry {
        Entry {
            key: KEY.parse().expect("the example key parses"),
            who: "Adam Harris <adam@example.com>".to_owned(),
        }
    }

    #[test]
    fn an_entry_renders_what_it_was_read_from() {
        let text = entry().render();
        assert_eq!(Entry::parse(&text), Ok(Some(entry())));
    }

    #[test]
    fn the_explanation_states_nothing() {
        assert_eq!(Entry::parse(EXPLANATION), Ok(None));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let text = format!("# who I believe\n\n{}", entry().render());
        assert_eq!(Entry::parse(&text), Ok(Some(entry())));
    }

    #[test]
    fn a_header_this_grammar_does_not_name_is_refused() {
        let text = format!("{}roles reviewer\n", entry().render());
        assert!(matches!(
            Entry::parse(&text),
            Err(EntryError::Unknown { .. })
        ));
    }

    #[test]
    fn a_second_key_is_refused_rather_than_taken() {
        let text = format!("{}key {KEY}\n", entry().render());
        assert!(matches!(
            Entry::parse(&text),
            Err(EntryError::Repeated { header: "key", .. })
        ));
    }

    /// A key with slashes all through it, which is the shape that made the
    /// digest the fallback: whatever `who` turns out to be, what comes back is
    /// one filename. Found originally by a test that failed one run in four.
    fn slashy() -> Key {
        "RWR1w/Qc/pmAfGpNp/rGIihJys120vcNACuzskkIWVdxuUe3Dzk3MlLz"
            .parse()
            .expect("a key with slashes in it")
    }

    #[test]
    fn a_default_label_is_who_the_key_speaks_for() {
        assert_eq!(
            default_label(&slashy(), "Adam Harris <adam@diaryx.org>"),
            "Adam Harris"
        );
        assert_eq!(default_label(&slashy(), "Adam Harris"), "Adam Harris");
        // A run of spaces is one, and the address is not part of the name.
        assert_eq!(
            default_label(&slashy(), "  Adam   Harris   <adam@diaryx.org>"),
            "Adam Harris"
        );
    }

    /// `who` is free text, so every answer has to be one filename.
    #[test]
    fn a_default_label_is_a_filename_whatever_who_says() {
        for who in [
            "Adam/Harris",
            "../../etc/passwd",
            "C:\\keys\\adam",
            ".hidden",
            "a\u{7}b",
        ] {
            let label = default_label(&slashy(), who);
            assert!(is_a_label(&label), "`{label}` from `{who}`");
            assert!(!label.contains('/'), "`{label}` from `{who}`");
            assert!(!label.starts_with('.'), "`{label}` from `{who}`");
        }
    }

    /// Where nothing usable survives, the digest of the key — which is a
    /// filename whatever the key and the person are called.
    #[test]
    fn a_who_that_names_nobody_falls_back_to_the_key() {
        for who in ["", "...", "<>", "/", "   "] {
            let label = default_label(&slashy(), who);
            assert_eq!(label.len(), 12, "`{label}` from `{who}`");
            assert!(
                label.chars().all(|c| c.is_ascii_hexdigit()),
                "`{label}` from `{who}`"
            );
            assert!(is_a_label(&label));
        }
    }

    /// A `who` landing on the name the explanation file already has would make
    /// `add` refuse for a reason nobody could see.
    #[test]
    fn a_who_that_names_the_explanation_falls_back_to_the_key() {
        let label = default_label(&slashy(), "how-this-works");
        assert_ne!(label, "how-this-works");
        assert_eq!(label.len(), 12);
    }

    /// Long enough for a name, short enough that the file still has one.
    #[test]
    fn a_very_long_who_is_cut() {
        let label = default_label(&slashy(), &"x".repeat(500));
        assert_eq!(label.chars().count(), LABEL_CHARS);
        assert!(is_a_label(&label));
    }

    #[test]
    fn a_label_that_is_a_path_is_refused() {
        assert!(!is_a_label(""));
        assert!(!is_a_label("."));
        assert!(!is_a_label(".."));
        assert!(!is_a_label("a/b"));
        assert!(is_a_label("adam"));
        assert!(is_a_label("adam's laptop"));
    }

    #[test]
    fn an_entry_without_a_person_is_refused() {
        let text = format!("{PREAMBLE}\nkey {KEY}\n");
        assert_eq!(
            Entry::parse(&text),
            Err(EntryError::Missing { header: "who" })
        );
    }
}
