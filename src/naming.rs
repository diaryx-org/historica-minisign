//! Where a claim is filed, and what it is called there.
//!
//! Decision 0003, on Historica's decision 0003's rule: *identity comes from
//! content, filenames are presentation*. Nothing here is load-bearing. A store
//! whose claims are all named by digest is a correct store and [`crate::verify`]
//! reads it without noticing, exactly as Historica reads a store whose
//! revisions are named that way. What this module is for is the folder a person
//! opens — and, unlike Historica's own naming, the file a person writes by
//! hand, which cannot be named after its own hash before it exists.
//!
//! ```text
//! claims/2026-04/2026-04-12 Initial commit — author.claim.txt
//! claims/2026-08/2026-08-18 drop the private export — author.claim.txt
//! claims/2026-08/2026-08-18 drop the private export — reviewer.claim.txt
//! ```
//!
//! A claim is filed beside the revision it vouches for, under the stem
//! Historica gave that revision — which brings decision 0041's month directory
//! and decision 0006's date and summary along without restating either. Signing
//! an old revision today therefore files the claim beside the old work rather
//! than under today's month, which is the normal case for this tool rather than
//! the edge: a review happens long after the thing reviewed.
//!
//! The one hard rule is Historica's, inherited whole: two replicas holding one
//! claim must produce one name for it, so a collision appends something derived
//! from the claim and never a counter, which would depend on what else is in
//! the directory.

use std::collections::BTreeMap;

use historica::core::RevisionId;
use historica::format::{RevisionDocument, Timestamp};
use historica::naming::stems as revision_stems;

use crate::claim::{Claim, Key};

/// Characters of a key's digest where a name needs one to tell two apart.
///
/// Of the *digest*, and never of the key's own text, which is the obvious idea
/// and a wrong one for the reason [`crate::trust::default_label`] gives: a
/// minisign key is spelled in base64, base64 holds `/`, and a stem is split on
/// `/` into the directories it names. Roughly one key in fourteen would put a
/// path separator in this suffix and file its claim somewhere nobody asked for.
pub const KEY_CHARS: usize = 8;

/// Characters of a claim digest where nothing else tells two claims apart.
pub const CLAIM_DIGEST_CHARS: usize = 12;

/// Characters of a timestamp that spell its month: `2026-08`.
///
/// A [`Timestamp`] has one spelling of fixed ASCII width, so this is a prefix
/// rather than a parse — Historica's own trick, for the same reason.
const MONTH_CHARS: usize = 7;

/// Characters of a timestamp that spell its date: `2026-08-18`.
const DATE_CHARS: usize = 10;

/// What separates the revision's stem from the role appended to it.
///
/// A bare space would run the role into a summary that ends in a word, and the
/// two would not be tellable apart by eye — which is the only thing this scheme
/// exists to buy.
pub const SEPARATOR: &str = " — ";

/// The stem every claim is filed under, keyed by the claim's own digest.
///
/// Decision 0003's three tiers, which are decision 0006's: the revision's stem
/// and the role, then the key, then the claim's digest. Each suffix is derived
/// from the claim, so two replicas arranging one set of claims produce one set
/// of names.
pub fn stems<'a>(
    claims: impl IntoIterator<Item = (&'a RevisionId, &'a Claim)>,
    documents: impl IntoIterator<Item = (&'a RevisionId, &'a RevisionDocument)>,
) -> BTreeMap<RevisionId, String> {
    let revisions = revision_stems(documents);

    let mut by_base: BTreeMap<String, Vec<(RevisionId, &Claim)>> = BTreeMap::new();
    for (digest, claim) in claims {
        by_base
            .entry(base(claim, &revisions))
            .or_default()
            .push((*digest, claim));
    }

    let mut out = BTreeMap::new();
    for (base, sharing) in by_base {
        if let [(digest, _)] = sharing.as_slice() {
            out.insert(*digest, base);
            continue;
        }

        // Two claims over one revision in one role: whose they are is what
        // differs, so the key is what parts them.
        let mut by_key: BTreeMap<String, Vec<(RevisionId, &Claim)>> = BTreeMap::new();
        for (digest, claim) in sharing {
            by_key
                .entry(format!("{base} {}", key_prefix(&claim.key)))
                .or_default()
                .push((digest, claim));
        }
        for (name, sharing) in by_key {
            if let [(digest, _)] = sharing.as_slice() {
                out.insert(*digest, name);
                continue;
            }
            // One key, one revision, one role, twice — the same person vouching
            // again at another moment. Only `when` differs, and only the digest
            // spells that difference in a filename.
            for (digest, _) in sharing {
                out.insert(
                    digest,
                    format!("{name} {}", digest.abbreviate(CLAIM_DIGEST_CHARS)),
                );
            }
        }
    }
    out
}

/// The stem one claim takes as it is written, given the claims already filed.
///
/// Historica's decision 0019: a writer names the file it is creating rather
/// than renaming it afterwards. Where the plain name is taken by a claim that
/// is not this one, the new claim takes the next tier and the one already there
/// keeps the name it was written under. [`stems`] gives both a suffix, so
/// [`crate::verify`] notes the older one and `arrange` moves it if it is ever
/// run; both spellings are unambiguous in the meantime.
pub fn stem_for<'a>(
    digest: &RevisionId,
    claim: &Claim,
    documents: impl IntoIterator<Item = (&'a RevisionId, &'a RevisionDocument)>,
    existing: impl IntoIterator<Item = (&'a RevisionId, &'a Claim)>,
) -> String {
    let revisions = revision_stems(documents);
    let mine = base(claim, &revisions);

    let (mut sharing_base, mut sharing_key) = (false, false);
    for (held, other) in existing {
        if held == digest || base(other, &revisions) != mine {
            continue;
        }
        sharing_base = true;
        sharing_key |= other.key == claim.key;
    }

    if !sharing_base {
        return mine;
    }
    let named = format!("{mine} {}", key_prefix(&claim.key));
    if !sharing_key {
        return named;
    }
    format!("{named} {}", digest.abbreviate(CLAIM_DIGEST_CHARS))
}

/// A claim's name before any collision suffix.
///
/// The revision's own stem where this copy holds the revision, and the claim's
/// own `when` and subject where it does not. The fallback is deterministic from
/// the claim alone, which is what lets a copy that has never seen the revision
/// file the claim at all; `arrange` re-files it if the revision arrives.
fn base(claim: &Claim, revisions: &BTreeMap<RevisionId, String>) -> String {
    match revisions.get(&claim.revision) {
        Some(stem) => format!("{stem}{SEPARATOR}{}", claim.role),
        None => format!(
            "{}/{} {} {}",
            prefix(&claim.when, MONTH_CHARS),
            prefix(&claim.when, DATE_CHARS),
            claim.role,
            claim.revision.abbreviate(CLAIM_DIGEST_CHARS)
        ),
    }
}

/// The leading `chars` characters of a timestamp as it is spelled.
fn prefix(when: &Timestamp, chars: usize) -> String {
    when.to_string().chars().take(chars).collect()
}

/// How a key is spelled where a filename has to tell two of them apart.
///
/// [`crate::trust::default_label`]'s rule, reached the same way and spelled the
/// same: the digest of the key's text, which is hexadecimal and therefore a
/// filename whatever the key looks like.
pub fn key_prefix(key: &Key) -> String {
    historica::format::digest(key.as_str().as_bytes()).abbreviate(KEY_CHARS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole of the bug this spelling exists to avoid: a stem is split on
    /// `/` into the directories it names, and roughly one minisign key in
    /// fourteen holds a `/` in its first eight characters.
    #[test]
    fn a_key_prefix_is_a_filename_whatever_the_key_looks_like() {
        // A real key whose base64 spelling carries a `/`.
        let key: Key = "RWSEi0aqcNHqmF6NSeZGrsiFldgdRbBW3ls20/H8vLJersDSm6jzVKsJ"
            .parse()
            .expect("a key");
        let prefix = key_prefix(&key);

        assert_eq!(prefix.len(), KEY_CHARS);
        assert!(
            prefix.chars().all(|c| c.is_ascii_hexdigit()),
            "a digest and not the key's own text: {prefix}"
        );
        assert!(!prefix.contains('/'), "{prefix}");
        assert_ne!(
            prefix,
            key.as_str().chars().take(KEY_CHARS).collect::<String>(),
            "the key's own first characters are what this must not be"
        );
    }
}
