//! Writing a claim, and the signature beside it.
//!
//! Decision 0002 links minisign rather than calling it, and decision 0001 puts
//! one condition on that: what this writes is what the `minisign` command
//! writes. So the signature carries the comments minisign's own default
//! carries, and nothing here is spelled a way that would make an artifact
//! recognisable as this tool's rather than as minisign's.
//!
//! Both files are written with `create_new` and neither is ever rewritten.
//! Decision 0003 moved the name off the digest and onto [`crate::naming`]'s
//! scheme, and kept the property that mattered: a claim's *path* is still a
//! function of the claim, so two copies of a store union without a conflict and
//! signing twice still costs nothing. What changed is that the folder can be
//! read, and that a claim can be written by hand before it has been hashed.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use historica::core::RevisionId;
use historica::fs::Filesystem;
use historica::record::Clock;
use minisign::PublicKey;

/// minisign's own secret key, re-exported so a caller can hold one without
/// naming the crate this one links. Decision 0002: what this writes is what
/// minisign writes, and that includes the key it reads.
pub use minisign::SecretKey;

use crate::claim::{Claim, Key, Role};
use crate::layout::{claim_file, signature_file};

/// What minisign puts in an untrusted comment, and therefore what this puts
/// there.
///
/// Nothing informative goes here on purpose: the comment is untrusted, and a
/// reader who learns to read facts out of it has learned the wrong habit.
/// Everything a claim says is in the claim, where the signature covers it.
const UNTRUSTED_COMMENT: &str = "signature from minisign secret key";

/// A claim, written and signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// The claim's digest, which is its identity whatever it is called.
    pub digest: RevisionId,
    /// Where the claim is.
    pub claim: PathBuf,
    /// Where its signature is.
    pub signature: PathBuf,
    /// Whether the store already held this exact claim.
    ///
    /// Not a failure: the same person vouching for the same revision in the
    /// same role at the same moment is the same document, and the store keeps
    /// the copy it had.
    pub already: bool,
}

/// The claim a key would make about a revision, now.
///
/// The key is read out of the secret key rather than asked for, so a claim can
/// never name a key other than the one that signs it.
pub fn claim_for(
    revision: RevisionId,
    role: Role,
    secret: &SecretKey,
    clock: &dyn Clock,
) -> Result<Claim, SignError> {
    Ok(Claim {
        revision,
        role,
        key: public_key(secret)?,
        when: clock.now().map_err(|error| SignError::Clock {
            because: error.to_string(),
        })?,
    })
}

/// The public key a secret key belongs to, spelled as a claim spells it.
pub fn public_key(secret: &SecretKey) -> Result<Key, SignError> {
    let public = PublicKey::from_secret_key(secret).map_err(SignError::minisign)?;
    public.to_base64().parse().map_err(SignError::minisign)
}

/// Write a claim into the store at `stem`, with its signature beside it.
///
/// The stem is [`crate::naming`]'s answer and never this function's: a caller
/// that has read the claims already held is the only one that can tell which
/// collision tier applies, and a writer that guessed would be a writer that
/// later renames — which decision 0003 leaves to `arrange` alone.
pub fn write<F: Filesystem + ?Sized>(
    files: &F,
    root: &Path,
    claim: &Claim,
    stem: &str,
    secret: &SecretKey,
) -> Result<Signed, SignError> {
    if claim.key != public_key(secret)? {
        return Err(SignError::WrongKey {
            claim: claim.key.clone(),
        });
    }

    let bytes = claim.render().into_bytes();
    let digest = historica::format::digest(&bytes);
    let claim_path = claim_file(root, stem);
    let signature_path = signature_file(root, stem);
    let name = claim_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();

    // The month directory decision 0041 files a revision in, which the stem
    // carries and this is the first thing to need on disk.
    let directory = claim_path.parent().unwrap_or(root).to_path_buf();
    files
        .create_directory(&directory)
        .map_err(|error| SignError::io(&directory, error))?;

    let already = match files.create_new(&claim_path, &bytes) {
        Ok(()) => false,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => true,
        Err(error) => return Err(SignError::io(&claim_path, error)),
    };

    // Signed even when the claim was already there, because the claim may have
    // arrived from somebody else's copy without its signature, or with one this
    // key did not make. A signature already beside it is left alone: these
    // files are immutable, and minisign's own nonce means a second signature
    // over the same bytes is a different string that proves exactly as much.
    match files.create_new(
        &signature_path,
        signature(secret, &bytes, &name)?.as_bytes(),
    ) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(SignError::io(&signature_path, error)),
    }

    Ok(Signed {
        digest,
        claim: claim_path,
        signature: signature_path,
        already,
    })
}

/// A detached signature over `bytes`, spelled as `minisign -Sm` spells one.
///
/// `name` goes in the trusted comment because minisign's own default puts the
/// signed file's name there. It is covered by the global signature, so it is
/// not a lie waiting to happen — but nothing in this crate reads it either: a
/// claim is identified by the digest of its bytes, and decision 0003 is the
/// rule that no name anywhere is allowed to be the authority on that.
pub fn signature(secret: &SecretKey, bytes: &[u8], name: &str) -> Result<String, SignError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .map_err(|error| SignError::Clock {
            because: error.to_string(),
        })?;
    let trusted = format!("timestamp:{seconds}\tfile:{name}\thashed");
    let signature = minisign::sign(None, secret, bytes, Some(&trusted), Some(UNTRUSTED_COMMENT))
        .map_err(SignError::minisign)?;
    Ok(signature.into_string())
}

/// Why a claim could not be written.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignError {
    /// The claim names a key other than the one being signed with.
    WrongKey {
        /// What the claim names.
        claim: Key,
    },
    /// The clock could not answer.
    Clock {
        /// What it said.
        because: String,
    },
    /// minisign refused.
    Minisign {
        /// What it said.
        because: String,
    },
    /// The filesystem refused.
    Io {
        /// What was being written.
        path: PathBuf,
        /// What it said.
        error: io::Error,
    },
}

impl SignError {
    fn io(path: &Path, error: io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            error,
        }
    }

    fn minisign(error: impl fmt::Display) -> Self {
        Self::Minisign {
            because: error.to_string(),
        }
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKey { claim } => write!(
                f,
                "the claim names {claim}, which is not the key signing it; a \
                 claim states whose word it is, so the two cannot differ"
            ),
            Self::Clock { because } => write!(f, "the clock could not say when now is: {because}"),
            Self::Minisign { because } => write!(f, "minisign: {because}"),
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            _ => None,
        }
    }
}
