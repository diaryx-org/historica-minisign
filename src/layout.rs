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
//!     4d8f….claim.txt          one claim, named by the digest of its own bytes
//!     4d8f….claim.txt.minisig  its detached minisign signature
//!   trust/
//!     adam.txt                 one key this copy believes, labelled by hand
//! ```
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

/// Where the claim with this digest goes.
pub fn claim_file(root: &Path, digest: &RevisionId) -> PathBuf {
    claims(root).join(format!("{digest}{CLAIM_SUFFIX}"))
}

/// Where that claim's signature goes.
pub fn signature_file(root: &Path, digest: &RevisionId) -> PathBuf {
    claims(root).join(format!("{digest}{CLAIM_SUFFIX}{SIGNATURE_SUFFIX}"))
}

/// The digest a claim's filename states, if the name is one this tool wrote.
///
/// A name is a claim about the bytes under it, and [`crate::verify`] is what
/// checks whether it is a true one.
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
    fn a_claims_name_round_trips_through_its_digest() {
        let id = digest(b"whatever");
        let path = claim_file(Path::new("history"), &id);
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(digest_of_name(name), Some(id));
    }

    #[test]
    fn a_signature_names_the_claim_beside_it() {
        let id = digest(b"whatever");
        let signature = signature_file(Path::new("history"), &id);
        let claim = claim_file(Path::new("history"), &id);
        assert_eq!(
            signed_name(signature.file_name().unwrap().to_str().unwrap()),
            claim.file_name().unwrap().to_str()
        );
    }

    #[test]
    fn a_name_that_is_not_a_digest_names_no_claim() {
        assert_eq!(digest_of_name("notes.claim.txt"), None);
        assert_eq!(digest_of_name("4d8f.claim.txt"), None);
        assert_eq!(signed_name("something.minisig"), None);
    }
}
