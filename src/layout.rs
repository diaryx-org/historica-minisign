//! Where the tool's files are, and what they are called.
//!
//! Two directories at the store root, both reserved for this tool by
//! Historica's decision 0046, which also made Historica's tolerance of them a
//! promise rather than an accident: `check` walks the directories it names and
//! says nothing about the rest.
//!
//! ```text
//! history/
//!   claims/
//!     2026-08/
//!       2026-08-18 drop the private export — author.claim.txt
//!       2026-08-18 drop the private export — author.claim.txt.minisig
//!   trust/
//!     adam.txt                 one key this copy believes, labelled by hand
//! ```
//!
//! Decision 0003 is where a claim goes and what it is called there; [`crate::naming`]
//! computes it. Nothing in this module decides a name — it spells the suffixes
//! and reads them back, and a claim under any name at all is still a claim,
//! because identity comes from content.
//!
//! The store root is also the one directory `record` never walks, so nothing
//! here can be swept into the history it vouches for.

use std::path::{Path, PathBuf};

use historica::core::RevisionId;

/// Where claims live, under the store root.
pub const CLAIMS_DIR: &str = "claims";

/// Where the trust policy lives, under the store root.
pub const TRUST_DIR: &str = "trust";

/// What a claim's filename ends with.
pub const CLAIM_SUFFIX: &str = ".claim.txt";

/// What a signature's filename ends with.
///
/// minisign's own suffix, and that is the whole reason for it: `minisign -Vm
/// <claim>` finds the signature without being told where it is, which is what
/// makes checking a claim by hand the command a person already knows.
pub const SIGNATURE_SUFFIX: &str = ".minisig";

/// What a trust entry's filename ends with. The rest of the name is a label
/// somebody chose; nothing reads it.
pub const TRUST_SUFFIX: &str = ".txt";

/// The claims directory of the store rooted at `root`.
pub fn claims(root: &Path) -> PathBuf {
    root.join(CLAIMS_DIR)
}

/// The trust directory of the store rooted at `root`.
pub fn trust(root: &Path) -> PathBuf {
    root.join(TRUST_DIR)
}

/// Where a claim filed under `stem` goes.
///
/// The stem may name more than one component — decision 0041's month directory
/// arrives inside it — so this joins a relative path rather than a filename.
pub fn claim_file(root: &Path, stem: &str) -> PathBuf {
    let mut components: Vec<&str> = stem.split('/').collect();
    let name = components.pop().unwrap_or_default();
    let mut path = claims(root);
    path.extend(components);
    path.push(format!("{name}{CLAIM_SUFFIX}"));
    path
}

/// Where that claim's signature goes.
pub fn signature_file(root: &Path, stem: &str) -> PathBuf {
    let mut path = claim_file(root, stem);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();
    path.set_file_name(format!("{name}{SIGNATURE_SUFFIX}"));
    path
}

/// Whether this filename is a claim's, whatever the rest of it says.
///
/// The whole of what a name has to prove for its bytes to be read. Decision
/// 0003: a claim is identified by parsing it, so a name that is not the one
/// this tool would have chosen still names a claim.
pub fn is_claim_name(name: &str) -> bool {
    name.ends_with(CLAIM_SUFFIX)
}

/// The digest a claim's filename states, if the name states one at all.
///
/// A name is a claim about the bytes under it, and [`crate::verify`] is what
/// checks whether it is a true one. Under decision 0003 almost no name states a
/// digest: this recognises the ones written before it, and the last-resort tier
/// that still ends in one, so that a false digest stays the error it always
/// was.
pub fn digest_of_name(name: &str) -> Option<RevisionId> {
    name.strip_suffix(CLAIM_SUFFIX)?.parse().ok()
}

/// The claim a signature's filename names, if it names one.
pub fn signed_name(name: &str) -> Option<&str> {
    let claim = name.strip_suffix(SIGNATURE_SUFFIX)?;
    claim.ends_with(CLAIM_SUFFIX).then_some(claim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use historica::format::digest;

    #[test]
    fn a_stem_naming_a_month_becomes_two_components() {
        let path = claim_file(
            Path::new("history"),
            "2026-08/2026-08-18 drop the export — author",
        );
        assert_eq!(
            path,
            Path::new("history/claims/2026-08/2026-08-18 drop the export — author.claim.txt")
        );
    }

    #[test]
    fn a_stem_naming_no_month_is_one_component() {
        let path = claim_file(Path::new("history"), "whatever");
        assert_eq!(path, Path::new("history/claims/whatever.claim.txt"));
    }

    #[test]
    fn a_signature_names_the_claim_beside_it() {
        let stem = "2026-08/2026-08-18 drop the export — author";
        let signature = signature_file(Path::new("history"), stem);
        let claim = claim_file(Path::new("history"), stem);
        assert_eq!(
            signed_name(signature.file_name().unwrap().to_str().unwrap()),
            claim.file_name().unwrap().to_str()
        );
        assert_eq!(signature.parent(), claim.parent());
    }

    /// Decision 0003: what a name has to prove for its bytes to be read is the
    /// suffix and nothing else.
    #[test]
    fn any_name_at_all_names_a_claim() {
        assert!(is_claim_name("notes.claim.txt"));
        assert!(is_claim_name(
            "2026-08-18 drop the export — author.claim.txt"
        ));
        assert!(!is_claim_name("notes.txt"));
        assert!(!is_claim_name("notes.claim.txt.minisig"));
    }

    /// A digest name still states a digest, which is the one thing a name can
    /// be wrong about.
    #[test]
    fn a_digest_name_still_round_trips_through_its_digest() {
        let id = digest(b"whatever");
        let path = claim_file(Path::new("history"), &id.to_string());
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(digest_of_name(name), Some(id));
    }

    #[test]
    fn a_name_that_is_not_a_digest_names_no_claim() {
        assert_eq!(digest_of_name("notes.claim.txt"), None);
        assert_eq!(digest_of_name("4d8f.claim.txt"), None);
        assert_eq!(signed_name("something.minisig"), None);
    }
}
