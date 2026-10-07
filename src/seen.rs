//! What this copy has witnessed: for each key it believes, the highest head
//! statement it has seen that key make. Decision 0005.
//!
//! ```text
//! seen-0
//! key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
//! counter 7
//! statement 4b1d…
//! ```
//!
//! Historica's decision 0046: *a verifier keeps the highest counter it has seen
//! for each key and refuses a statement below it.* This is where it keeps it.
//! The file is under `trust/`, which historica's decision 0053 classes
//! `local-only`, because a high-water mark is the copy's opinion of what it has
//! been shown, and a store that could send a reader a lower one could undo the
//! only thing it is for.
//!
//! Unlike everything else this tool writes, a record here is rewritten: it is
//! one number per key, it only goes up, and nothing else ever reads it. It is
//! raised only by [`witness`], which a person runs, never by `verify`, which
//! reads and never writes.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use historica::core::RevisionId;
use historica::format::digest;
use historica::fs::{Filesystem, Kind, read_to_string};

use crate::claim::Key;
use crate::heads::parse_counter;
use crate::layout::seen as seen_dir;
use crate::verify::{Finding, Report};

/// The preamble a record begins with.
pub const PREAMBLE: &str = "seen-0";

/// What a record's filename ends with.
const SUFFIX: &str = ".txt";

/// The highest statement this copy has witnessed from one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witnessed {
    /// The key.
    pub key: Key,
    /// The counter of the statement witnessed.
    pub counter: u64,
    /// The statement's digest, so that a second statement at the same counter
    /// is told apart from the one that was seen.
    pub statement: RevisionId,
}

impl Witnessed {
    /// The record, as written.
    pub fn render(&self) -> String {
        format!(
            "{PREAMBLE}\nkey {}\ncounter {}\nstatement {}\n",
            self.key, self.counter, self.statement
        )
    }

    /// Read a record, refusing anything that is not one.
    pub fn parse(text: &str) -> Result<Self, String> {
        let lines: Vec<&str> = text
            .strip_suffix('\n')
            .ok_or("its last line has no newline")?
            .split('\n')
            .collect();
        let [preamble, key, counter, statement] = lines.as_slice() else {
            return Err("a record is four lines".to_owned());
        };
        if *preamble != PREAMBLE {
            return Err(format!(
                "it begins `{preamble}`, and a record begins `{PREAMBLE}`"
            ));
        }
        let field = |line: &str, header: &str| {
            line.strip_prefix(header)
                .and_then(|rest| rest.strip_prefix(' '))
                .map(str::to_owned)
                .ok_or(format!("it has no `{header}` line where one belongs"))
        };
        Ok(Self {
            key: field(key, "key")?
                .parse()
                .map_err(|error| format!("`key`: {error}"))?,
            counter: parse_counter(&field(counter, "counter")?)?,
            statement: field(statement, "statement")?
                .parse()
                .map_err(|_| "`statement`: a digest is 64 hexadecimal characters".to_owned())?,
        })
    }
}

/// Every record this copy keeps, and every file among them that is not one.
#[derive(Debug, Clone, Default)]
pub struct Seen {
    records: BTreeMap<Key, Witnessed>,
    malformed: Vec<(PathBuf, String)>,
}

impl Seen {
    /// Read what this copy has witnessed. No directory is a copy that has
    /// witnessed nothing, which is not an error.
    pub fn read<F: Filesystem + ?Sized>(files: &F, root: &Path) -> io::Result<Self> {
        let directory = seen_dir(root);
        let mut seen = Self::default();
        let entries = match files.entries(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(seen),
            Err(error) => return Err(error),
        };
        for entry in entries {
            let is_record = entry
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(SUFFIX) && !name.starts_with('.'));
            if !is_record || !matches!(files.look(&entry.path)?, Some(Kind::File)) {
                continue;
            }
            match Witnessed::parse(&read_to_string(files, &entry.path)?) {
                Ok(record) => {
                    seen.records.insert(record.key.clone(), record);
                }
                Err(because) => seen.malformed.push((entry.path, because)),
            }
        }
        Ok(seen)
    }

    /// The highest statement witnessed from `key`, if any.
    pub fn get(&self, key: &Key) -> Option<&Witnessed> {
        self.records.get(key)
    }

    /// Every record, by key.
    pub fn records(&self) -> impl Iterator<Item = &Witnessed> {
        self.records.values()
    }

    /// Files in the directory that are not records, and why.
    pub fn malformed(&self) -> impl Iterator<Item = (&Path, &str)> {
        self.malformed
            .iter()
            .map(|(path, because)| (path.as_path(), because.as_str()))
    }
}

/// Where the record for `key` is kept.
///
/// Named by the whole digest of the key's text rather than a prefix of it: two
/// keys sharing a prefix would share a file, and the second to be witnessed
/// would erase the first's high-water mark without a word.
pub fn record_file(root: &Path, key: &Key) -> PathBuf {
    seen_dir(root).join(format!("{}{SUFFIX}", digest(key.as_str().as_bytes())))
}

/// Raise this copy's record for every key whose latest statement `report`
/// found, and return the records written.
///
/// A key is skipped when the report found its statements equivocating, its
/// heads withheld, or its counter rolled back: witnessing a store in that state
/// would record the fault as the new normal. A record is never lowered.
pub fn witness<F: Filesystem + ?Sized>(
    files: &F,
    root: &Path,
    report: &Report,
) -> io::Result<Vec<Witnessed>> {
    let mut written = Vec::new();
    for (key, held) in report.latest() {
        let faulted = report.findings().any(|finding| match finding {
            Finding::Equivocated { key: faulty, .. }
            | Finding::Withheld { key: faulty, .. }
            | Finding::RolledBack { key: faulty, .. } => faulty == key,
            _ => false,
        });
        if faulted {
            continue;
        }
        let record = Witnessed {
            key: key.clone(),
            counter: held.statement.counter,
            statement: held.statement.digest(),
        };
        if report
            .seen()
            .get(key)
            .is_some_and(|seen| seen.counter >= record.counter)
        {
            continue;
        }
        let directory = seen_dir(root);
        files.create_directory(&directory)?;
        files.write(&record_file(root, key), record.render().as_bytes())?;
        written.push(record);
    }
    Ok(written)
}

impl fmt::Display for Witnessed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips() {
        let record = Witnessed {
            key: "RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
                .parse()
                .unwrap(),
            counter: 7,
            statement: digest(b"a statement"),
        };
        assert_eq!(Witnessed::parse(&record.render()), Ok(record));
        assert!(Witnessed::parse("seen-0\nkey x\n").is_err());
    }
}
