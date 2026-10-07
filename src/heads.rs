//! The head statement: one key, a counter, and the heads its history had at
//! that moment. Decision 0005.
//!
//! ```text
//! heads-0
//! key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
//! counter 7
//! when 2026-10-07T09:12:04-06:00
//! head 33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a
//! head 9a1c0e7d55b2f3e4a6c8d0f1b3a5c7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1
//! ```
//!
//! Historica's decision 0046 named this second document kind and left its
//! grammar here. A claim says *this revision is mine*; a head statement says
//! *this is everything I had*, which is the one thing a set of claims cannot
//! say. A signature never stops being valid, so a store can present a subset
//! of a history — every document intact, every claim verifying — and lie by
//! omission. A statement is what that subset is measured against.
//!
//! The grammar is decision 0001's, unchanged in spirit: exactly the lines the
//! preamble names, in that order, and a reader that meets anything else
//! refuses the document. The `head` lines are the one place a header repeats,
//! so the order inside them is fixed too — ascending by digest, no repeats —
//! which gives one statement exactly one spelling, and therefore one digest
//! and one file however many copies write it.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use historica::core::RevisionId;
use historica::format::{Timestamp, digest};

use crate::claim::Key;

/// The preamble a head statement begins with.
///
/// Numbered, like a claim's, and not a claim's: a `claim-0` reader that meets
/// one refuses it, which is the rule working — it cannot tell what a
/// statement vouches for, so it does not count it as vouching for anything.
pub const PREAMBLE: &str = "heads-0";

/// The headers before the heads, in the one order they may be stated.
const HEADERS: [&str; 3] = ["key", "counter", "when"];

/// The header every head is stated under.
const HEAD: &str = "head";

/// One key's word on what its history held, at one count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// Whose word this is.
    pub key: Key,
    /// Which of this key's statements it is: higher is later.
    ///
    /// A count and not a time, because a clock can be set back and a reader
    /// cannot tell. Every statement a key makes is higher than every one it
    /// made before on any copy it has seen, so a reader who has witnessed
    /// `7` refuses a store whose latest is `6`.
    pub counter: u64,
    /// When the key said it. Informative only: nothing compares it.
    pub when: Timestamp,
    /// The heads the key's history had, by digest. Never empty.
    pub heads: BTreeSet<RevisionId>,
}

impl Statement {
    /// The document, as the bytes that get signed and hashed.
    pub fn render(&self) -> String {
        let mut text = format!(
            "{PREAMBLE}\nkey {}\ncounter {}\nwhen {}\n",
            self.key, self.counter, self.when
        );
        for head in &self.heads {
            text.push_str(&format!("{HEAD} {head}\n"));
        }
        text
    }

    /// Read a statement, refusing anything its grammar does not name.
    pub fn parse(text: &str) -> Result<Self, StatementError> {
        let Some(body) = text.strip_suffix('\n') else {
            return Err(StatementError::NoFinalNewline);
        };
        let lines: Vec<&str> = body.split('\n').collect();
        if lines[0] != PREAMBLE {
            return Err(StatementError::Preamble {
                found: lines[0].to_owned(),
            });
        }

        let mut values = Vec::with_capacity(HEADERS.len());
        for (index, expected) in HEADERS.iter().enumerate() {
            let at = index + 2;
            let Some(line) = lines.get(index + 1) else {
                return Err(StatementError::Missing { header: expected });
            };
            let (found, value) = line.split_once(' ').unwrap_or((line, ""));
            if found != *expected {
                return Err(StatementError::Unexpected {
                    at,
                    found: found.to_owned(),
                    expected,
                });
            }
            values.push((at, value));
        }
        let malformed =
            |at: usize, header: &'static str, because: String| StatementError::Malformed {
                at,
                header,
                because,
            };

        let (at, value) = values[0];
        let key = value
            .parse::<Key>()
            .map_err(|error| malformed(at, "key", error.to_string()))?;
        let (at, value) = values[1];
        let counter = parse_counter(value).map_err(|because| malformed(at, "counter", because))?;
        let (at, value) = values[2];
        let when = value
            .parse::<Timestamp>()
            .map_err(|error| malformed(at, "when", error.to_string()))?;

        let mut heads = BTreeSet::new();
        let mut last: Option<RevisionId> = None;
        for (index, line) in lines.iter().enumerate().skip(HEADERS.len() + 1) {
            let at = index + 1;
            let (found, value) = line.split_once(' ').unwrap_or((line, ""));
            if found != HEAD {
                return Err(StatementError::Unexpected {
                    at,
                    found: found.to_owned(),
                    expected: HEAD,
                });
            }
            let head = value.parse::<RevisionId>().map_err(|_| {
                malformed(at, HEAD, "a digest is 64 hexadecimal characters".to_owned())
            })?;
            // Ascending and never repeated, so that one statement has one
            // spelling: a reader that sorted for itself would agree with the
            // signer about the set and disagree about the bytes.
            if last.is_some_and(|last| head <= last) {
                return Err(malformed(
                    at,
                    HEAD,
                    "heads are stated once each, in ascending order".to_owned(),
                ));
            }
            last = Some(head);
            heads.insert(head);
        }
        if heads.is_empty() {
            return Err(StatementError::Missing { header: HEAD });
        }

        Ok(Self {
            key,
            counter,
            when,
            heads,
        })
    }

    /// The statement's own name: the SHA-256 of the bytes [`Statement::render`]
    /// writes, as a claim's is.
    pub fn digest(&self) -> RevisionId {
        digest(self.render().as_bytes())
    }
}

impl fmt::Display for Statement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// A counter as a statement spells it: a decimal number from one up, with no
/// sign and no leading zero, so that one count has one spelling.
pub fn parse_counter(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("a counter is a decimal number".to_owned());
    }
    if value.starts_with('0') {
        return Err("a counter starts at 1 and has no leading zero".to_owned());
    }
    value
        .parse::<u64>()
        .map_err(|_| "a counter fits in sixty-four bits".to_owned())
}

/// Why some bytes are not a head statement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatementError {
    /// The last line has no newline after it.
    NoFinalNewline,
    /// The first line is not `heads-0`.
    Preamble {
        /// What it was.
        found: String,
    },
    /// A header the grammar requires is not there.
    Missing {
        /// Which.
        header: &'static str,
    },
    /// A line other than the one the grammar names at that place.
    Unexpected {
        /// The line, counted from one.
        at: usize,
        /// The header it states.
        found: String,
        /// The header the grammar wanted there.
        expected: &'static str,
    },
    /// A header whose value is not spelled as that header's values are.
    Malformed {
        /// The line, counted from one.
        at: usize,
        /// The header.
        header: &'static str,
        /// What is wrong.
        because: String,
    },
}

impl fmt::Display for StatementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFinalNewline => f.write_str("its last line has no newline"),
            Self::Preamble { found } => {
                write!(
                    f,
                    "it begins `{found}`, and a head statement begins `{PREAMBLE}`"
                )
            }
            Self::Missing { header } => write!(f, "it has no `{header}` line"),
            Self::Unexpected {
                at,
                found,
                expected,
            } => write!(
                f,
                "line {at} states `{found}` where `{expected}` belongs; a reader \
                 refuses a line it was not told to expect"
            ),
            Self::Malformed {
                at,
                header,
                because,
            } => write!(f, "line {at}, `{header}`: {because}"),
        }
    }
}

impl std::error::Error for StatementError {}

impl FromStr for Statement {
    type Err = StatementError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    const LOW: &str = "33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a";
    const HIGH: &str = "9a1c0e7d55b2f3e4a6c8d0f1b3a5c7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1";

    fn text(counter: &str, heads: &[&str]) -> String {
        let mut text =
            format!("heads-0\nkey {KEY}\ncounter {counter}\nwhen 2026-10-07T09:12:04-06:00\n");
        for head in heads {
            text.push_str(&format!("head {head}\n"));
        }
        text
    }

    #[test]
    fn a_statement_round_trips_through_its_one_spelling() {
        let written = text("7", &[LOW, HIGH]);
        let statement = Statement::parse(&written).expect("a statement");
        assert_eq!(statement.counter, 7);
        assert_eq!(statement.heads.len(), 2);
        assert_eq!(statement.render(), written);
        assert_eq!(statement.digest(), digest(written.as_bytes()));
    }

    #[test]
    fn heads_out_of_order_or_repeated_are_refused() {
        assert!(matches!(
            Statement::parse(&text("7", &[HIGH, LOW])),
            Err(StatementError::Malformed { header: "head", .. })
        ));
        assert!(matches!(
            Statement::parse(&text("7", &[LOW, LOW])),
            Err(StatementError::Malformed { header: "head", .. })
        ));
    }

    #[test]
    fn a_statement_of_no_heads_is_refused() {
        assert_eq!(
            Statement::parse(&text("7", &[])),
            Err(StatementError::Missing { header: "head" })
        );
    }

    #[test]
    fn a_counter_has_one_spelling() {
        for bad in ["0", "07", "-1", "+1", "seven", ""] {
            assert!(
                matches!(
                    Statement::parse(&text(bad, &[LOW])),
                    Err(StatementError::Malformed {
                        header: "counter",
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
    }

    /// Decision 0001's rule, applied here: a line a later grammar adds is
    /// refused, never skipped.
    #[test]
    fn a_line_the_grammar_does_not_name_is_refused() {
        let narrowed = text("7", &[LOW]).replace("when ", "expires 2027-01-01\nwhen ");
        assert!(matches!(
            Statement::parse(&narrowed),
            Err(StatementError::Unexpected { at: 4, .. })
        ));
        let trailing = format!("{}x-note hello\n", text("7", &[LOW]));
        assert!(matches!(
            Statement::parse(&trailing),
            Err(StatementError::Unexpected {
                expected: "head",
                ..
            })
        ));
    }

    #[test]
    fn a_claim_is_not_a_statement() {
        let claim = format!(
            "claim-0\nrevision {LOW}\nrole author\nkey {KEY}\nwhen 2026-10-07T09:12:04-06:00\n"
        );
        assert!(matches!(
            Statement::parse(&claim),
            Err(StatementError::Preamble { .. })
        ));
    }
}
