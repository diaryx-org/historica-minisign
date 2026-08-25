//! Turning what a person typed into a revision the store holds.
//!
//! Historica's decision 0001 spends a section on this argument position: change
//! IDs are spelled in `k`–`z` and digests in hex, "so one command-line argument
//! position can accept either without ambiguity". This is a second
//! implementation of that rule, and it is one deliberately: Historica's own
//! lives in its binary rather than its library, so the alternative to writing
//! it here is asking Historica to publish it. That is a change to Historica
//! with a version number on it, and this tool is not the reason to make it —
//! but the vocabulary is copied exactly, because a person who learns
//! `historica log 3a` should be able to type `historica-sign sign 3a`.

use historica::core::{ChangeId, ChangeState, RevisionId};
use historica::store::{Name, Store};

use super::Failure;

/// The revision a target names.
pub fn resolve(store: &Store, spelling: &str) -> Result<RevisionId, Failure> {
    if spelling.is_empty() {
        return Err(Failure::usage("a target cannot be empty"));
    }

    // A bookmark called `head` still wins, because a name somebody chose beats
    // a word the tool reserved.
    if spelling == "head" && store.name(spelling).is_none() {
        return the_head(store)?.ok_or_else(|| Failure::error("this store holds no revisions"));
    }

    if let Some(bookmark) = store.name(spelling) {
        return match bookmark {
            Name::Revision(id) => held(store, id, &format!("the bookmark `{spelling}`")),
            Name::Change(change) => current(store, change, &format!("the bookmark `{spelling}`")),
            Name::File(file) => Err(Failure::error(format!(
                "the bookmark `{spelling}` names the file {file}, and a claim \
                 vouches for a revision"
            ))),
        };
    }

    if spelling
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        return by_prefix(store, spelling);
    }
    if spelling
        .chars()
        .all(|character| ('k'..='z').contains(&character))
    {
        let change = change_by_prefix(store, spelling)?;
        return current(store, change, &format!("`{spelling}`"));
    }

    Err(Failure::error(format!(
        "`{spelling}` is not a bookmark here, and it is spelled as neither a \
         change ID (`k`–`z`) nor a digest (`0`–`9`, `a`–`f`)"
    )))
}

/// The one head to sign against, or a refusal naming the choice.
///
/// Historica's decision 0023: an amended revision is still a head by parent
/// edges, so the superseded ones come out first.
pub fn the_head(store: &Store) -> Result<Option<RevisionId>, Failure> {
    let heads = historica_sign::verify::current_heads(store);
    match heads.len() {
        0 => Ok(None),
        1 => Ok(heads.into_iter().next()),
        several => {
            let mut message = format!(
                "this store has {several} heads, so nothing here is `the` \
                 latest; name the one you mean:"
            );
            for head in &heads {
                message.push_str(&format!("\n  {}", head.abbreviate(12)));
            }
            Err(Failure::error(message))
        }
    }
}

/// A revision the store holds, or a refusal saying it does not.
fn held(store: &Store, id: RevisionId, called: &str) -> Result<RevisionId, Failure> {
    if store.get(&id).is_some() {
        Ok(id)
    } else {
        Err(Failure::error(format!(
            "{called} names {}, which this store does not hold",
            id.abbreviate(12)
        )))
    }
}

/// The current revision of a change, or a refusal saying why there is not one.
fn current(store: &Store, change: ChangeId, called: &str) -> Result<RevisionId, Failure> {
    match store.history().change_state(&change) {
        ChangeState::Resolved(revision) => Ok(revision.id),
        ChangeState::Unknown => Err(Failure::error(format!(
            "{called} names the change {change}, and no revision here claims it"
        ))),
        ChangeState::Abandoned => Err(Failure::error(format!(
            "{called} names the change {change}, whose every revision was \
             superseded elsewhere"
        ))),
        ChangeState::Divergent(revisions) => {
            let mut message = format!(
                "{called} names the change {change}, which has {} concurrent \
                 revisions; a claim vouches for one, so name it:",
                revisions.len()
            );
            for revision in &revisions {
                message.push_str(&format!("\n  {}", revision.abbreviate(12)));
            }
            Err(Failure::error(message))
        }
    }
}

fn by_prefix(store: &Store, prefix: &str) -> Result<RevisionId, Failure> {
    let matches: Vec<RevisionId> = store
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| id.to_string().starts_with(prefix))
        .collect();
    match matches.as_slice() {
        [] => Err(Failure::error(format!(
            "no revision here has a digest beginning `{prefix}`"
        ))),
        [only] => Ok(*only),
        several => {
            let mut message = format!("`{prefix}` names {} revisions:", several.len());
            for id in several {
                message.push_str(&format!("\n  {}", id.abbreviate(12)));
            }
            Err(Failure::error(message))
        }
    }
}

fn change_by_prefix(store: &Store, prefix: &str) -> Result<ChangeId, Failure> {
    let matches: Vec<ChangeId> = store
        .history()
        .changes()
        .into_iter()
        .filter(|change| change.to_string().starts_with(prefix))
        .collect();
    match matches.as_slice() {
        [] => Err(Failure::error(format!("no change here begins `{prefix}`"))),
        [only] => Ok(*only),
        several => {
            let mut message = format!("`{prefix}` names {} changes:", several.len());
            for change in several {
                message.push_str(&format!("\n  {change}"));
            }
            Err(Failure::error(message))
        }
    }
}
