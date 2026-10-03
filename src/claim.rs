//! The claim document: one key, one revision, one role, one moment — and,
//! since decision 0004, optionally one file.
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
//! already limited. So every claim is exactly the lines its preamble names, in
//! that order, and anything else is malformed.
//!
//! Decision 0004 is the first time the grammar grew, and it grew exactly as
//! 0001 said it would: a narrowing is a new preamble. `claim-1` vouches for one
//! file as it stood at a revision, and names that file's content digest:
//!
//! ```text
//! claim-1
//! revision 33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a
//! file kmnpqrstvwxzkmnpqrstvwxz
//! content sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
//! role reviewer
//! key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
//! when 2026-10-03T09:12:04-06:00
//! ```
//!
//! A `claim-0` reader meets `file` where it expects `role` and refuses the
//! document, which is the rule working: it cannot tell that the claim was
//! narrowed, so it does not count it as covering anything.
//!
//! A claim carries no message. The signature covers the whole document, so
//! prose would be safe, but a claim's worth is that it says exactly one thing;
//! see 0001's rejected alternatives.

use std::fmt;
use std::str::FromStr;

use historica::core::{FileId, RevisionId};
use historica::format::{Timestamp, digest};
use minisign_verify::PublicKey;

/// The preamble a whole-revision claim begins with.
///
/// Spelled with its number, unlike Historica's bare `historica`: a claim is not
/// a Historica document and must never be mistaken for one, and this grammar
/// grows by minting `claim-1` rather than by loosening what `claim-0` accepts.
pub const PREAMBLE: &str = "claim-0";

/// The preamble a claim over one file begins with. Decision 0004.
pub const FILE_PREAMBLE: &str = "claim-1";

/// The headers of a `claim-0`, in the one order it may state them.
const HEADERS: [&str; 4] = ["revision", "role", "key", "when"];

/// The headers of a `claim-1`, in the one order it may state them: what is
/// vouched for first, then in what capacity, by whom, and when.
const FILE_HEADERS: [&str; 6] = ["revision", "file", "content", "role", "key", "when"];

/// One key vouching for one revision, or for one file at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The revision vouched for, by digest.
    ///
    /// A digest and never a change ID: a claim over a change would follow
    /// amendment, which is exactly the property a signature must not have.
    pub revision: RevisionId,
    /// Whether the claim covers the whole revision or one file at it, and
    /// which preamble it is therefore written under.
    pub scope: Scope,
    /// In what capacity.
    pub role: Role,
    /// Whose word this is.
    pub key: Key,
    /// When they said it.
    pub when: Timestamp,
}

/// What a claim covers.
///
/// Not `#[non_exhaustive]`, deliberately: a third scope would be a narrowing a
/// caller has never judged, and a `match` that stops compiling is that caller
/// being told so — the same refusal decision 0001 asks of a reader.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope {
    /// The whole revision, and by its digest everything it descends from.
    /// Written as `claim-0`.
    Revision,
    /// One file as it stood at the revision. Written as `claim-1`.
    ///
    /// Covers no other file, and nothing the revision descends from.
    File {
        /// The file, by Historica's file ID, which a rename does not change.
        file: FileId,
        /// The file's content digest, as the claimant's tool computed it.
        ///
        /// Opaque here. This crate checks its spelling and never computes it,
        /// because which bytes of a file are *content* is the claimant's
        /// tool's knowledge: for pedantic it is prov's digest of a document
        /// without its `confirmed:` list. What it is for is a reader's tool
        /// comparing it with the file's content digest *now*.
        content: ContentDigest,
    },
}

impl Claim {
    /// The preamble this claim is written under, which its scope decides.
    pub fn preamble(&self) -> &'static str {
        match self.scope {
            Scope::Revision => PREAMBLE,
            Scope::File { .. } => FILE_PREAMBLE,
        }
    }

    /// The file and content digest a one-file claim names, or `None` for a
    /// claim over a whole revision.
    pub fn file(&self) -> Option<(&FileId, &ContentDigest)> {
        match &self.scope {
            Scope::Revision => None,
            Scope::File { file, content } => Some((file, content)),
        }
    }

    /// The document, as the bytes that get signed and hashed.
    ///
    /// A whole-revision claim is always `claim-0`, never a `claim-1` with the
    /// file lines left out: one claim has one spelling, so one claim is one
    /// file however many times and wherever it is written, and a reader built
    /// before decision 0004 still reads every whole-revision claim.
    pub fn render(&self) -> String {
        match &self.scope {
            Scope::Revision => format!(
                "{PREAMBLE}\nrevision {}\nrole {}\nkey {}\nwhen {}\n",
                self.revision, self.role, self.key, self.when
            ),
            Scope::File { file, content } => format!(
                "{FILE_PREAMBLE}\nrevision {}\nfile {file}\ncontent {content}\nrole {}\nkey {}\nwhen {}\n",
                self.revision, self.role, self.key, self.when
            ),
        }
    }

    /// Read a claim, refusing anything its grammar does not name.
    pub fn parse(text: &str) -> Result<Self, ClaimError> {
        // `split` rather than `lines`, so a missing final newline and a stray
        // blank line are both visible rather than silently tolerated: the bytes
        // are what is signed, and a reader that normalises them is a reader
        // that disagrees with the signer about what was signed.
        let Some(body) = text.strip_suffix('\n') else {
            return Err(ClaimError::NoFinalNewline);
        };
        let lines: Vec<&str> = body.split('\n').collect();

        // The preamble picks the grammar, and nothing else may: a reader that
        // guessed the grammar from the headers would be a reader that read a
        // `claim-1`'s file lines as optional.
        let headers: &[&'static str] = match lines[0] {
            PREAMBLE => &HEADERS,
            FILE_PREAMBLE => &FILE_HEADERS,
            found => {
                return Err(ClaimError::Preamble {
                    found: found.to_owned(),
                });
            }
        };
        let mut values = Vec::with_capacity(headers.len());
        for (index, expected) in headers.iter().enumerate() {
            let at = index + 2;
            let Some(line) = lines.get(index + 1) else {
                return Err(ClaimError::Missing { header: expected });
            };
            let (found, value) = match line.split_once(' ') {
                Some(split) => split,
                None => (*line, ""),
            };
            if found != *expected {
                return Err(if headers.contains(&found) {
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
            values.push((at, *expected, value));
        }
        // After the headers rather than before, so that a line a later grammar
        // inserted is named as the header it is — the diagnosis decision 0001
        // is about — rather than counted as one line too many.
        if lines.len() > headers.len() + 1 {
            return Err(ClaimError::Trailing {
                at: headers.len() + 2,
            });
        }

        // Every header is in place, so each is found by name rather than by
        // position, which is the one thing the two grammars disagree about.
        // Only names the chosen grammar holds are asked for below.
        let line = |header: &str| {
            let (at, _, value) = values
                .iter()
                .find(|(_, name, _)| *name == header)
                .copied()
                .expect("a header the grammar names");
            (at, value)
        };
        let malformed = |at: usize, header: &'static str, because: String| ClaimError::Malformed {
            at,
            header,
            because,
        };

        let (at, value) = line("revision");
        let revision = value.parse::<RevisionId>().map_err(|_| {
            malformed(
                at,
                "revision",
                "a digest is 64 hexadecimal characters".to_owned(),
            )
        })?;
        let scope = if lines[0] == FILE_PREAMBLE {
            let (at, value) = line("file");
            let file = value
                .parse::<FileId>()
                .map_err(|error| malformed(at, "file", error.to_string()))?;
            let (at, value) = line("content");
            let content = value
                .parse::<ContentDigest>()
                .map_err(|error| malformed(at, "content", error.to_string()))?;
            Scope::File { file, content }
        } else {
            Scope::Revision
        };
        let (at, value) = line("role");
        let role = value
            .parse::<Role>()
            .map_err(|error| malformed(at, "role", error.to_string()))?;
        let (at, value) = line("key");
        let key = value
            .parse::<Key>()
            .map_err(|error| malformed(at, "key", error.to_string()))?;
        let (at, value) = line("when");
        let when = value
            .parse::<Timestamp>()
            .map_err(|error| malformed(at, "when", error.to_string()))?;

        Ok(Self {
            revision,
            scope,
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

/// A file's content digest, as the tool that computed it spells it:
/// `sha256:9f86d0…`.
///
/// Decision 0004: an algorithm, a colon, and a value. The algorithm is one to
/// sixteen characters of `a`–`z`, `0`–`9` and `-`, beginning with a letter;
/// the value is one to 128 characters of ASCII letters, digits, `-` and `_`,
/// which holds hexadecimal and unpadded URL-safe base64 alike.
///
/// That is the whole of what this crate knows about it. It never computes one
/// and never normalises one — two digests are the same when they are the same
/// characters — because the comparison that gives a one-file claim its worth,
/// this digest against the file's content digest now, is made by a tool that
/// knows what the file's content is. The algorithm is required so that such a
/// tool can tell a digest it cannot compare from one that differs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentDigest(String);

/// The longest an algorithm's name may be.
const ALGORITHM_LIMIT: usize = 16;

/// The longest a digest's value may be: SHA-512 in hexadecimal.
const DIGEST_LIMIT: usize = 128;

impl ContentDigest {
    /// The digest, as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// What comes before the colon: `sha256`.
    pub fn algorithm(&self) -> &str {
        self.0
            .split_once(':')
            .map_or("", |(algorithm, _)| algorithm)
    }

    /// What comes after it.
    pub fn value(&self) -> &str {
        self.0.split_once(':').map_or("", |(_, value)| value)
    }
}

impl FromStr for ContentDigest {
    type Err = MalformedContentDigest;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let fail = |because| Err(MalformedContentDigest { because });
        let Some((algorithm, value)) = text.split_once(':') else {
            return fail("it has no `:` between an algorithm and a value");
        };
        if algorithm.is_empty() || algorithm.len() > ALGORITHM_LIMIT {
            return fail("its algorithm is not one to sixteen characters");
        }
        if !algorithm.starts_with(|c: char| c.is_ascii_lowercase())
            || !algorithm
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return fail("its algorithm is not `a`–`z`, `0`–`9` and `-`, beginning with a letter");
        }
        if value.is_empty() || value.len() > DIGEST_LIMIT {
            return fail("its value is not one to 128 characters");
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return fail("its value holds something that is not a letter, a digit, `-` or `_`");
        }
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A content digest that was not spelled as one is spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedContentDigest {
    because: &'static str,
}

impl fmt::Display for MalformedContentDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a content digest is `<algorithm>:<value>`, as in `sha256:9f86d0…`, and {}",
            self.because
        )
    }
}

impl std::error::Error for MalformedContentDigest {}

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
/// Every variant names the line, because a claim is five or seven lines and
/// saying which one is the whole of the diagnosis.
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
                "line 1 says `{found}`; a claim begins `{PREAMBLE}` or \
                 `{FILE_PREAMBLE}`, and a reader that met another spelling \
                 would be guessing at what it was leaving out"
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

    const FILE_EXAMPLE: &str = "\
claim-1
revision 33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a
file kmnpqrstvwxzkmnpqrstvwxz
content sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
role reviewer
key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
when 2026-10-03T09:12:04-06:00
";

    fn file_example() -> Claim {
        Claim::parse(FILE_EXAMPLE).expect("the example parses")
    }

    #[test]
    fn a_whole_revision_claim_is_claim_0() {
        let claim = example();
        assert_eq!(claim.scope, Scope::Revision);
        assert_eq!(claim.preamble(), PREAMBLE);
        assert_eq!(claim.file(), None);
    }

    #[test]
    fn a_claim_over_one_file_renders_the_bytes_it_was_read_from() {
        let claim = file_example();
        assert_eq!(claim.render(), FILE_EXAMPLE);
        assert_eq!(claim.preamble(), FILE_PREAMBLE);
        let (file, content) = claim.file().expect("a file");
        assert_eq!(file.to_string(), "kmnpqrstvwxzkmnpqrstvwxz");
        assert_eq!(content.algorithm(), "sha256");
        assert_eq!(content.value().len(), 64);
    }

    /// One claim, one spelling: dropping the file from a `claim-1` is a
    /// `claim-0`, byte for byte, and not a `claim-1` with lines missing.
    #[test]
    fn narrowing_and_widening_change_the_preamble() {
        let mut claim = file_example();
        claim.scope = Scope::Revision;
        assert!(claim.render().starts_with("claim-0\n"));
        assert_eq!(Claim::parse(&claim.render()), Ok(claim));
    }

    /// Decision 0001's rule, working as it said it would: a reader of the old
    /// grammar meets the narrowing line and refuses the document.
    #[test]
    fn a_claim_1_body_under_claim_0_is_refused_at_its_file_line() {
        let text = FILE_EXAMPLE.replace(FILE_PREAMBLE, PREAMBLE);
        assert_eq!(
            Claim::parse(&text),
            Err(ClaimError::Unknown {
                at: 3,
                found: "file".to_owned()
            })
        );
    }

    /// And the other way: a `claim-1` without its file lines is not a claim
    /// over the whole revision. The preamble decides the grammar.
    #[test]
    fn a_claim_0_body_under_claim_1_is_refused() {
        let text = EXAMPLE.replace(PREAMBLE, FILE_PREAMBLE);
        assert!(matches!(
            Claim::parse(&text),
            Err(ClaimError::OutOfOrder {
                at: 3,
                expected: "file",
                ..
            })
        ));
    }

    #[test]
    fn a_claim_1_refuses_a_header_its_grammar_does_not_name() {
        let text = FILE_EXAMPLE.replace("role reviewer", "expires 2027-01-01T00:00:00+00:00");
        assert!(matches!(
            Claim::parse(&text),
            Err(ClaimError::Unknown { at: 5, .. })
        ));
    }

    #[test]
    fn a_claim_1_refuses_its_headers_out_of_order() {
        let text = FILE_EXAMPLE.replace(
            "file kmnpqrstvwxzkmnpqrstvwxz\ncontent sha256:",
            "content sha256:",
        );
        let text = text.replace(
            "\nrole reviewer",
            "\nfile kmnpqrstvwxzkmnpqrstvwxz\nrole reviewer",
        );
        assert!(matches!(
            Claim::parse(&text),
            Err(ClaimError::OutOfOrder {
                at: 3,
                expected: "file",
                ..
            })
        ));
    }

    #[test]
    fn a_claim_1_refuses_a_missing_or_repeated_line() {
        let missing = FILE_EXAMPLE.replace("when 2026-10-03T09:12:04-06:00\n", "");
        assert_eq!(
            Claim::parse(&missing),
            Err(ClaimError::Missing { header: "when" })
        );
        let repeated = FILE_EXAMPLE.replace(
            "file kmnpqrstvwxzkmnpqrstvwxz\n",
            "file kmnpqrstvwxzkmnpqrstvwxz\nfile kmnpqrstvwxzkmnpqrstvwxz\n",
        );
        assert!(matches!(
            Claim::parse(&repeated),
            Err(ClaimError::OutOfOrder { at: 4, .. })
        ));
        let trailing = format!("{FILE_EXAMPLE}looks fine to me\n");
        assert_eq!(Claim::parse(&trailing), Err(ClaimError::Trailing { at: 8 }));
    }

    #[test]
    fn a_claim_1_refuses_a_file_that_is_not_a_file_id() {
        let text = FILE_EXAMPLE.replace("file kmnpqrstvwxzkmnpqrstvwxz", "file notes.md");
        assert!(matches!(
            Claim::parse(&text),
            Err(ClaimError::Malformed {
                at: 3,
                header: "file",
                ..
            })
        ));
    }

    #[test]
    fn a_claim_1_refuses_content_that_is_not_a_digest() {
        let text = FILE_EXAMPLE.replace("content sha256:", "content ");
        assert!(matches!(
            Claim::parse(&text),
            Err(ClaimError::Malformed {
                at: 4,
                header: "content",
                ..
            })
        ));
    }

    #[test]
    fn a_content_digest_is_an_algorithm_and_a_value() {
        assert!("sha256:9f86d0".parse::<ContentDigest>().is_ok());
        assert!("blake3:AbC-_9".parse::<ContentDigest>().is_ok());
        assert!("sha-512:00".parse::<ContentDigest>().is_ok());
        for bad in [
            "",
            "9f86d0",
            ":9f86d0",
            "sha256:",
            "SHA256:9f86d0",
            "256sha:9f86d0",
            "sha256:9f86 d0",
            "sha256:9f86/d0",
            "sha256:9f86:d0",
            "an-algorithm-name-too-long:00",
        ] {
            assert!(bad.parse::<ContentDigest>().is_err(), "{bad:?}");
        }
        assert!(
            format!("sha512:{}", "0".repeat(DIGEST_LIMIT))
                .parse::<ContentDigest>()
                .is_ok()
        );
        assert!(
            format!("sha512:{}", "0".repeat(DIGEST_LIMIT + 1))
                .parse::<ContentDigest>()
                .is_err()
        );
    }

    /// Never normalised: two digests are equal when they are the same
    /// characters, because the tool comparing them is not this one.
    #[test]
    fn a_content_digest_is_compared_as_written() {
        let lower: ContentDigest = "sha256:abcd".parse().unwrap();
        let upper: ContentDigest = "sha256:ABCD".parse().unwrap();
        assert_ne!(lower, upper);
    }

    #[test]
    fn a_preamble_neither_grammar_names_is_refused() {
        let text = EXAMPLE.replace(PREAMBLE, "claim-2");
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
