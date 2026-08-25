//! Signed claims that vouch for Historica revisions.
//!
//! Historica's decision 0046 — *who vouches for a revision* — observes that
//! every revision document states an `author` and nothing checks it, and that
//! the digest machinery answers *whether these are the bytes* while saying
//! nothing about *whose word they are*. Its answer is that the trust layer is a
//! separate tool writing more readable files, because a revision document
//! cannot carry a signature over itself: its identity is the SHA-256 of its own
//! bytes, and a document cannot contain a signature over a digest that depends
//! on the signature.
//!
//! This is that tool. It writes two kinds of file and reads a third:
//!
//! - a **claim** ([`claim`]) in `history/claims/`, one key vouching for one
//!   revision digest in one role at one moment, named by the SHA-256 of its own
//!   bytes;
//! - its **signature**, minisign, detached, beside it;
//! - the **trust policy** ([`trust`]) in `history/trust/`, one key to a file,
//!   which says whose word this copy accepts and never crosses a store
//!   boundary.
//!
//! Nothing here writes a Historica document, and Historica knows nothing about
//! any of it beyond the promise 0046 extracted: a directory at the store root
//! that Historica does not name belongs to whichever tool wrote it.
//!
//! # Verifying without signing
//!
//! [`verify`] is the half that must be cheap to depend on, so `sign` is a
//! feature and `default-features = false` leaves a library that only ever
//! reads. That is not hypothetical tidiness: 0046 defers *enforcement at
//! receive* — a `receive` that refuses history no trusted key vouches for —
//! and if that is ever built it must not drag key generation and a secret-key
//! parser into a version-control core.
//!
//! # Checking a claim without this tool
//!
//! Two commands, and neither is Historica nor this crate:
//!
//! ```console
//! $ minisign -Vm 4d8f….claim.txt -P RWTd8LRC…
//! $ shasum -a 256 history/revisions/2026-08/….rev.txt
//! ```
//!
//! Decision 0002 requires that to keep working: what this crate writes is what
//! the `minisign` command writes, and what the command writes is accepted here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claim;
pub mod layout;

pub use claim::{Claim, ClaimError, Key, Role};
