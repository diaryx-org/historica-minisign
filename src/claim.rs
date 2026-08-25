//! The claim document: one key, one revision, one role, one moment.
//!
//! ```text
//! claim-0
//! revision 33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a
//! role reviewer
//! key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
//! when 2026-08-24T09:12:04-06:00
//! ```
//!
//! Historica's decision 0046 fixed that shape; decision 0001 here fixes the
//! grammar around it, and the load-bearing half of that is what a reader does
//! with a line it does not recognise: **it refuses the document**. Historica
//! hashes and ignores an `x-` header because a document it does not fully
//! understand still states what it states. A claim is read to answer *should I
//! believe this*, and a header a future grammar adds is far more likely to
//! narrow a claim than to widen it — an `expires`, a `scope`, an `only-for`.
//! A reader that skipped such a line would accept a claim its author had
//! already limited. So every claim is exactly five lines, in this order, and
//! anything else is malformed.
//!
//! A claim carries no message. The signature covers the whole document, so
//! prose would be safe, but a claim's worth is that it says exactly one thing;
//! see 0001's rejected alternatives.

use std::fmt;
use std::str::FromStr;

use historica::core::RevisionId;
use historica::format::{Timestamp, digest};
use minisign_verify::PublicKey;

/// The preamble every claim begins with.
///
/// Spelled with its number, unlike Historica's bare `historica`: a claim is not
/// a Historica document and must never be mistaken for one, and this grammar
/// grows by minting `claim-1` rather than by loosening what `claim-0` accepts.
pub const PREAMBLE: &str = "claim-0";

/// The headers, in the one order a claim may state them.
const HEADERS: [&str; 4] = ["revision", "role", "key", "when"];

/// One key vouching for one revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The revision vouched for, by digest.
    ///
    /// A digest and never a change ID: a claim over a change would follow
    /// amendment, which is exactly the property a signature must not have.
    pub revision: RevisionId,
    /// In what capacity.
    pub role: Role,
    /// Whose word this is.
    pub key: Key,
    /// When they said it.
    pub when: Timestamp,
}

impl Claim {
    /// The document, as the bytes that get signed and hashed.
    pub fn render(&self) -> String {
        format!(
            "{PREAMBLE}\nrevision {}\nrole {}\nkey {}\nwhen {}\n",
            self.revision, self.role, self.key, self.when
        )
    }

    /// Read a claim, refusing anything this grammar does not name.
    pub fn parse(text: &str) -> Result<Self, ClaimError> {
        // `split` rather than `lines`, so a missing final newline and a stray
        // blank line are both visible rather than silently tolerated: the bytes
        // are what is signed, and a reader that normalises them is a reader
        // that disagrees with the signer about what was signed.
        let Some(body) = text.strip_suffix('\n') else {
            return Err(ClaimError::NoFinalNewline);
        };
        let lines: Vec<&str> = body.split('\n').collect();

        if lines[0] != PREAMBLE {
            return Err(ClaimError::Preamble {
                found: lines[0].to_owned(),
            });
        }
        if lines.len() > HEADERS.len() + 1 {
            return Err(ClaimError::Trailing {
                at: HEADERS.len() + 2,
            });
        }

        let mut values = Vec::with_capacity(HEADERS.len());
        for (index, expected) in HEADERS.iter().enumerate() {
            let at = index + 2;
            let Some(line) = lines.get(index + 1) else {
                return Err(ClaimError::Missing { header: expected });
            };
            let (found, value) = match line.split_once(' ') {
                Some(split) => split,
                None => (*line, ""),
            };
            if found != *expected {
                return Err(if HEADERS.contains(&found) {
                    ClaimError::OutOfOrder {
                        at,
                        found: found.to_owned(),
                        expected,
                    }
                } else {
                    ClaimError::Unknown {
                        at,
                        found: found.to_owned(),
                    }
                });
            }
            values.push((at, value));
        }

        let malformed = |at: usize, header: &'static str, because: String| ClaimError::Malformed {
            at,
            header,
            because,
        };

        let revision = values[0].1.parse::<RevisionId>().map_err(|_| {
            malformed(
                values[0].0,
                "revision",
                "a digest is 64 hexadecimal characters".to_owned(),
            )
        })?;
        let role = values[1]
            .1
            .parse::<Role>()
            .map_err(|error| malformed(values[1].0, "role", error.to_string()))?;
        let key = values[2]
            .1
            .parse::<Key>()
            .map_err(|error| malformed(values[2].0, "key", error.to_string()))?;
        let when = values[3]
            .1
            .parse::<Timestamp>()
            .map_err(|error| malformed(values[3].0, "when", error.to_string()))?;

        Ok(Self {
            revision,
            role,
            key,
            when,
        })
    }

    /// The claim's own name: the SHA-256 of the bytes [`Claim::render`] writes.
    ///
    /// Historica's [`digest`] rather than a second hasher, so that
    /// `shasum -a 256` prints the same thing about a claim as it does about
    /// every document beside it.
    pub fn digest(&self) -> RevisionId {
        digest(self.render().as_bytes())
    }
}

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// In what capacity a key vouches: `author`, `reviewer`, `release`, or whatever
/// else a person is actually doing.
///
/// One to thirty-two characters from `a`–`z` and `-`, beginning and ending with
/// a letter. No spaces, because the line is read positionally; no vocabulary,
/// because a role is what a person says they were doing and this tool has no
/// standing to refuse a fourth one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Role(String);

/// The longest a role may be. Long enough for a phrase, short enough that the
/// line stays a line.
const ROLE_LIMIT: usize = 32;

impl Role {
    /// The role, as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Role {
    type Err = MalformedRole;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let because = if value.is_empty() {
            Some("it is empty")
        } else if value.len() > ROLE_LIMIT {
            Some("it is longer than thirty-two characters")
        } else if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        {
            Some("it holds something that is not `a`–`z` or `-`")
        } else if value.starts_with('-') || value.ends_with('-') {
            Some("it begins or ends with `-`")
        } else {
            None
        };
        match because {
            Some(because) => Err(MalformedRole { because }),
            None => Ok(Self(value.to_owned())),
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A role that was not spelled as a role is spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedRole {
    because: &'static str,
}

impl fmt::Display for MalformedRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a role is one to thirty-two characters of `a`–`z` and `-`, and {}",
            self.because
        )
    }
}

impl std::error::Error for MalformedRole {}

/// A minisign public key, spelled as `minisign.pub` spells it.
///
/// Held as the text rather than as bytes because the text is what a person
/// copies between a claim, a trust entry, and a `minisign -Vm -P` on the
/// command line — and because two spellings of one key would be a way for a
/// claim and a policy to disagree while looking identical.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key(String);

impl Key {
    /// The key, as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The key, ready to verify with.
    ///
    /// Infallible in practice — the text was parsed through minisign on the way
    /// in — but the decoding is redone rather than cached, so this type stays
    /// one string and nothing else.
    pub fn public_key(&self) -> Result<PublicKey, minisign_verify::Error> {
        PublicKey::from_base64(&self.0)
    }
}

impl FromStr for Key {
    type Err = MalformedKey;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // minisign's own decoder is the authority on what a key is: length,
        // algorithm, and all. Writing a second opinion here is how a claim
        // starts naming keys that `minisign -Vm` will not take.
        PublicKey::from_base64(value).map_err(|_| MalformedKey)?;
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Something that was not a minisign public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedKey;

impl fmt::Display for MalformedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "a key is a minisign public key: the fifty-six characters \
             `minisign.pub` holds on its second line",
        )
    }
}

impl std::error::Error for MalformedKey {}

/// Why a claim could not be read.
///
/// Every variant names the line, because a claim is five lines and saying which
/// one is the whole of the diagnosis.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimError {
    /// The first line was not [`PREAMBLE`].
    Preamble {
        /// What it said instead.
        found: String,
    },
    /// A header this grammar requires is not there.
    Missing {
        /// The one that is missing.
        header: &'static str,
    },
    /// A header this grammar names, in a position it does not belong.
    OutOfOrder {
        /// The line it was on.
        at: usize,
        /// What was found there.
        found: String,
        /// What belongs there.
        expected: &'static str,
    },
    /// A header this grammar does not name.
    Unknown {
        /// The line it was on.
        at: usize,
        /// What it called itself.
        found: String,
    },
    /// A header whose value is not what that header holds.
    Malformed {
        /// The line it was on.
        at: usize,
        /// Which header.
        header: &'static str,
        /// What is wrong with the value.
        because: String,
    },
    /// Content after the last header.
    Trailing {
        /// Where it starts.
        at: usize,
    },
    /// The document does not end with a newline.
    NoFinalNewline,
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preamble { found } => write!(
                f,
                "line 1 says `{found}`; a claim begins `{PREAMBLE}`, and a \
                 reader that met another spelling would be guessing at what it \
                 was leaving out"
            ),
            Self::Missing { header } => {
                write!(f, "there is no `{header}` line, and a claim states one")
            }
            Self::OutOfOrder {
                at,
                found,
                expected,
            } => write!(
                f,
                "line {at} states `{found}` where `{expected}` belongs; a \
                 claim's headers are in one order, which is what makes its \
                 bytes the same bytes wherever it was written"
            ),
            Self::Unknown { at, found } => write!(
                f,
                "line {at} states `{found}`, which this grammar does not name. \
                 A claim is refused rather than read past: a header a later \
                 grammar adds is likelier to narrow the claim than to widen it"
            ),
            Self::Malformed {
                at,
                header,
                because,
            } => write!(f, "line {at}'s `{header}` is wrong: {because}"),
            Self::Trailing { at } => write!(
                f,
                "line {at} is past the last header, and a claim carries no \
                 message"
            ),
            Self::NoFinalNewline => f.write_str("the document does not end with a newline"),
        }
    }
}

impl std::error::Error for ClaimError {}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "\
claim-0
revision 33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a
role reviewer
key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
when 2026-08-24T09:12:04-06:00
";

    fn example() -> Claim {
        Claim::parse(EXAMPLE).expect("the example parses")
    }

    #[test]
    fn a_claim_renders_the_bytes_it_was_read_from() {
        assert_eq!(example().render(), EXAMPLE);
    }

    #[test]
    fn a_claims_name_is_the_digest_of_its_own_bytes() {
        assert_eq!(example().digest(), digest(EXAMPLE.as_bytes()));
    }

    #[test]
    fn a_header_this_grammar_does_not_name_is_refused() {
        let text = EXAMPLE.replace("role reviewer", "expires 2027-01-01T00:00:00+00:00");
        assert!(matches!(
            Claim::parse(&text),
            Err(ClaimError::Unknown { at: 3, .. })
        ));
    }

    #[test]
    fn headers_out_of_order_are_refused() {
        let text = EXAMPLE.replace(
            "revision 33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a\nrole reviewer",
            "role reviewer\nrevision 33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a",
        );
        assert!(matches!(
            Claim::parse(&text),
            Err(ClaimError::OutOfOrder { at: 2, .. })
        ));
    }

    #[test]
    fn a_message_is_refused() {
        let text = format!("{EXAMPLE}\nlooks fine to me\n");
        assert!(matches!(
            Claim::parse(&text),
            Err(ClaimError::Trailing { .. })
        ));
    }

    #[test]
    fn a_missing_final_newline_is_refused() {
        let text = EXAMPLE.trim_end_matches('\n');
        assert_eq!(Claim::parse(text), Err(ClaimError::NoFinalNewline));
    }

    #[test]
    fn a_wrong_preamble_is_refused() {
        let text = EXAMPLE.replace(PREAMBLE, "historica");
        assert!(matches!(
            Claim::parse(&text),
            Err(ClaimError::Preamble { .. })
        ));
    }

    #[test]
    fn a_claim_1_is_refused_by_a_claim_0_reader() {
        let text = EXAMPLE.replace(PREAMBLE, "claim-1");
        assert!(matches!(
            Claim::parse(&text),
            Err(ClaimError::Preamble { .. })
        ));
    }

    #[test]
    fn a_role_is_letters_and_hyphens() {
        assert!("reviewer".parse::<Role>().is_ok());
        assert!("release-manager".parse::<Role>().is_ok());
        assert!("".parse::<Role>().is_err());
        assert!("-reviewer".parse::<Role>().is_err());
        assert!("reviewer-".parse::<Role>().is_err());
        assert!("Reviewer".parse::<Role>().is_err());
        assert!("second reviewer".parse::<Role>().is_err());
        assert!("x".repeat(ROLE_LIMIT + 1).parse::<Role>().is_err());
    }

    #[test]
    fn a_key_is_whatever_minisign_will_take() {
        assert!(
            "RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
                .parse::<Key>()
                .is_ok()
        );
        assert!("RWTd8LRC".parse::<Key>().is_err());
        assert!("".parse::<Key>().is_err());
    }

    /// A missing value is a malformed header rather than a missing one — the
    /// line is there, and saying otherwise would send somebody looking for a
    /// line they can see.
    #[test]
    fn a_header_with_no_value_is_malformed() {
        let text = EXAMPLE.replace("role reviewer", "role");
        assert!(matches!(
            Claim::parse(&text),
            Err(ClaimError::Malformed { header: "role", .. })
        ));
    }
}
