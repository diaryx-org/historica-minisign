//! The command-line front end.
//!
//! `sign` writes a claim and its signature into `history/claims/`, and
//! `state` a head statement beside them (decision 0005); `trust` writes, rewrites and
//! deletes files in `history/trust/`, and `witness` raises this copy's record
//! of what it has seen there. `verify` reads, and Historica's decision 0046
//! says so in as many words. Nothing here writes a Historica document, ever.

#[cfg(feature = "http")]
mod fetch;
mod target;

use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use historica::format::Timestamp;
use historica::fs::Filesystem;
use historica::record::{Clock, Platform};
use historica::store::{Store, StoreError};
use historica::wrote::{self, Line};

use historica::core::{FileId, RevisionId};

use historica_minisign::claim::{Claim, ContentDigest, Key, Role};
use historica_minisign::layout::{
    CLAIM_SUFFIX, SIGNATURE_SUFFIX, claim_file, claims, signature_file,
};
use historica_minisign::verify::{FileCheck, Finding, Severity};
use historica_minisign::{key, naming, seen, sign, trust, verify};

/// What `historica-minisign` with no arguments prints.
pub fn usage() -> String {
    format!("{COMMANDS}{READING}\n{NOTES}")
}

/// The commands every build has.
const COMMANDS: &str = "\
usage: historica-minisign [-C <dir>] <command> [<arguments>]

  sign [<target>] [--role <role>] [--key <path>] [--password-file <path>]
       [--file <path or file ID> --content <digest>]
                           vouch for a revision: write a claim into
                           history/claims/ and sign it. The role is what you
                           were doing — `author`, `reviewer`, `release`, or
                           whatever you say — and defaults to `author`. A
                           claim covers everything the revision descends
                           from, so signing the head signs the history. The
                           password is asked for at the terminal unless
                           --password-file names a file, or `-` for stdin.
                           With --file and --content, vouch for that one file
                           as it stood at the revision, and nothing else;
                           <digest> is its content digest as your tool spells
                           it (`sha256:…`), which this tool records and never
                           computes
  sign --wrote <path> [--role <role>] [--key <path>] [--password-file <path>]
                           vouch for every revision a historica command said
                           it wrote: <path>, or `-` for stdin, holds what
                           that command printed with --fields, so
                             historica record --fields -m x \
                               | historica-minisign sign --wrote -
                           signs what `record` just wrote. A statement that
                           wrote nothing signs nothing and succeeds; one this
                           build cannot read signs nothing and fails
  state [--key <path>] [--password-file <path>]
                           state every head this store has, signed, at a
                           count one higher than any this key has stated
                           before. A copy that has witnessed the statement
                           refuses a store that later holds less than it
                           names, or an older statement in its place
  witness                  record, for every key this copy believes, the
                           latest statement `verify` found, so that a later
                           store rolled back to before it is refused. Kept in
                           history/trust/seen/, which never travels
  arrange [--dry-run] [--prune]
                           re-file every claim under the name this tool would
                           choose for it, renaming and never rewriting. Only
                           this command renames. --prune also deletes a file
                           holding a claim another file already holds, after
                           checking the bytes are the same
  verify [<target>] [--complete]
                           check every claim the store holds against the keys
                           in history/trust/. Errors mean something here is
                           wrong; notes are observations. With a target, say
                           whether that revision is vouched for. --complete
                           also fails when a head is vouched for by nobody
  trust add <key> <who> [--label <label>]
  trust list
  trust remove <label>     the keys this copy believes. One key to a file;
                           <who> is a label for a person, not an identity
                           anything checks. Nothing ever writes this from
                           another store — receiving a store receives its
                           history and its claims, never its opinion of who
                           to believe
  trust revoke <label> [--as-of <time>]
                           stop counting what that key signs from <time>
                           (`2026-10-19T08:30:00-06:00`; by default now). Its
                           claims from before still count. Name the earliest
                           time it may have leaked: the key signs whatever
                           time it is given
  key new [--at <dir>] [--password-file <path>]
                           write a minisign key pair, by default in
                           ~/.minisign. A key `minisign -G` wrote works here
                           unchanged, and so does this one there
  key show [--public <path>]
                           the public key line, which is what goes in a trust
                           entry and in `minisign -Vm -P`
";

/// The commands that read over HTTP, in a build that has a transport.
///
/// `#[cfg]`ed as historica's own `fetch` line is (its decision 0057): a usage
/// text naming a command this binary does not have would be the one line in
/// it that is not true.
#[cfg(feature = "http")]
const READING: &str = "\
  fetch <url> [--join-unrelated] [--no-bytes] [--fields] [--key <path>]
        [--password-file <path>]
                           `historica fetch`, with every request signed by
                           your key, for a copy a server keeps to the people
                           it lets read. <url> is the manifest's,
                           conventionally offer.txt. Each request carries
                           `Authorization: Minisign <key-id> <time>
                           <signature>`, good for that one path for minutes
  fetch <url> <path>...    take the bytes of the files named, and nothing else
  token <hub> [--key <path>] [--password-file <path>]
                           ask a hub for a short-lived token for your key, and
                           print it as JSON: what `git clone` takes as a
                           password where it cannot sign
";

/// Nothing, in a build without one.
#[cfg(not(feature = "http"))]
const READING: &str = "";

/// What the commands share.
const NOTES: &str = "\
a <target> is `head`, a bookmark, a change ID, or a revision digest; the last
two may be abbreviated to any unambiguous prefix, and their alphabets do not
overlap, so one argument accepts either.

a claim is a file, its signature is minisign's, and checking one by hand is
`minisign -Vm <claim> -P <key>` followed by `shasum -a 256` on the revision it
names. writing one by hand is the same shape: five lines in a text editor, in
history/claims/, under any name ending `.claim.txt`, and `minisign -Sm` on it.
a claim is read by what it says and not by what it is called, so `arrange` is
what puts a hand-written one where the rest are filed.
";

/// Why a command stopped, and what the process should exit with.
#[derive(Debug)]
pub struct Failure {
    message: Option<String>,
    code: u8,
    usage: bool,
}

impl Failure {
    /// Something went wrong: exit 1, having said why.
    pub fn error(message: impl fmt::Display) -> Self {
        Self {
            message: Some(message.to_string()),
            code: 1,
            usage: false,
        }
    }

    /// The command line itself was wrong: exit 2, and print the usage.
    pub fn usage(message: impl fmt::Display) -> Self {
        Self {
            message: Some(message.to_string()),
            code: 2,
            usage: true,
        }
    }

    /// What to print, if anything.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Whether the usage text belongs after the message.
    pub fn wants_usage(&self) -> bool {
        self.usage
    }

    /// The process exit code.
    pub fn code(&self) -> u8 {
        self.code
    }
}

impl From<StoreError> for Failure {
    fn from(error: StoreError) -> Self {
        Self::error(error)
    }
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self::error(error)
    }
}

/// Run one command line, returning the code to exit with.
pub fn run(arguments: impl IntoIterator<Item = String>) -> Result<u8, Failure> {
    let mut arguments = arguments.into_iter();
    let mut base: Option<PathBuf> = None;

    let command = loop {
        let Some(argument) = arguments.next() else {
            return printing(|out| out.write_all(usage().as_bytes()));
        };
        match argument.as_str() {
            "-C" => {
                let directory = arguments
                    .next()
                    .ok_or_else(|| Failure::usage("`-C` wants a directory"))?;
                base = Some(PathBuf::from(directory));
            }
            "-h" | "--help" | "help" => return printing(|out| out.write_all(usage().as_bytes())),
            "-V" | "--version" => {
                return printing(|out| {
                    writeln!(out, "historica-minisign {}", env!("CARGO_PKG_VERSION"))
                });
            }
            other if other.starts_with('-') => {
                return Err(Failure::usage(format!("`{other}` is not an option here")));
            }
            _ => break argument,
        }
    };

    let rest: Vec<String> = arguments.collect();
    let base = base.unwrap_or_else(|| PathBuf::from("."));

    match command.as_str() {
        "sign" => sign_command(&base, &rest),
        "verify" => verify_command(&base, &rest),
        "state" => state_command(&base, &rest),
        "witness" => witness_command(&base, &rest),
        "arrange" => arrange_command(&base, &rest),
        "trust" => trust_command(&base, &rest),
        "key" => key_command(&rest),
        #[cfg(feature = "http")]
        "fetch" => fetch::fetch(&base, &rest),
        #[cfg(feature = "http")]
        "token" => fetch::token(&rest),
        // Named rather than left to fall through, as historica's own build
        // without a transport names its `fetch`: "not a command" would be
        // true of this binary and false of this tool.
        #[cfg(not(feature = "http"))]
        "fetch" | "token" => Err(Failure::usage(format!(
            "this historica-minisign was built without the `http` feature, so \
             it has no transport for `{command}`; `historica_minisign::request` \
             signs a request for a host that brings its own"
        ))),
        other => Err(Failure::usage(format!("`{other}` is not a command"))),
    }
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

fn sign_command(base: &Path, arguments: &[String]) -> Result<u8, Failure> {
    let mut spelling: Option<String> = None;
    let mut role = "author".to_owned();
    let mut key_path: Option<PathBuf> = None;
    let mut password_file: Option<PathBuf> = None;
    let mut file: Option<String> = None;
    let mut content: Option<String> = None;
    let mut wrote: Option<PathBuf> = None;

    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--role" => role = value(&mut rest, "--role")?,
            "--wrote" => wrote = Some(PathBuf::from(value(&mut rest, "--wrote")?)),
            "--file" => file = Some(value(&mut rest, "--file")?),
            "--content" => content = Some(value(&mut rest, "--content")?),
            "--key" => key_path = Some(PathBuf::from(value(&mut rest, "--key")?)),
            "--password-file" => {
                password_file = Some(PathBuf::from(value(&mut rest, "--password-file")?));
            }
            other if other.starts_with("--") => {
                return Err(Failure::usage(format!(
                    "`{other}` is not an option to sign"
                )));
            }
            other if spelling.is_none() => spelling = Some(other.to_owned()),
            other => {
                return Err(Failure::usage(format!(
                    "`{other}`: sign vouches for one revision"
                )));
            }
        }
    }

    let role: Role = role
        .parse()
        .map_err(|error| Failure::usage(format!("--role: {error}")))?;
    // Decision 0004: a claim over one file names both, or it is a claim over
    // the whole revision and names neither.
    let one_file = match (file, content) {
        (None, None) => None,
        (Some(file), Some(content)) => {
            let content: ContentDigest = content
                .parse()
                .map_err(|error| Failure::usage(format!("--content: {error}")))?;
            Some((file, content))
        }
        (Some(_), None) => {
            return Err(Failure::usage(
                "--file wants --content: a claim over one file names the \
                 content it vouched for",
            ));
        }
        (None, Some(_)) => {
            return Err(Failure::usage(
                "--content wants --file: it is the content of one file",
            ));
        }
    };

    if let Some(wrote) = wrote {
        return sign_wrote(
            base,
            &wrote,
            spelling.as_deref(),
            one_file.is_some(),
            role,
            key_path,
            password_file,
        );
    }

    let store = open(base)?;
    let revision = match spelling.as_deref() {
        Some(spelling) => target::resolve(&store, spelling)?,
        None => target::the_head(&store)?.ok_or_else(|| {
            Failure::error("this store holds no revisions, so there is nothing to vouch for")
        })?,
    };

    let secret = secret_key(key_path, password_file.as_deref())?;
    let filed = file_claim(&store, revision, one_file, role, &secret)?;
    printing(|out| {
        filed.print(out)?;
        filed.who(out)
    })
}

/// `sign --wrote`: every `revision` line of a `historica-wrote-1` statement,
/// signed as `sign <digest>` would sign it, read with historica's own parser
/// (its decision 0074) rather than a second one.
///
/// The statement is the target, so nothing else may name one, and the head
/// fallback does not apply. All of it is checked before anything is signed:
/// one this build cannot read is discarded whole, per 0074, and one naming a
/// revision this store does not hold signs none of the ones it does.
fn sign_wrote(
    base: &Path,
    wrote: &Path,
    spelling: Option<&str>,
    one_file: bool,
    role: Role,
    key_path: Option<PathBuf>,
    password_file: Option<PathBuf>,
) -> Result<u8, Failure> {
    let stdin = Path::new("-");
    if let Some(spelling) = spelling {
        return Err(Failure::usage(format!(
            "`{spelling}`: --wrote is the target, so sign takes no other"
        )));
    }
    if one_file {
        return Err(Failure::usage(
            "--wrote vouches for whole revisions; a claim over one file names \
             its revision as a target",
        ));
    }
    if wrote == stdin && password_file.as_deref() == Some(stdin) {
        return Err(Failure::usage(
            "--wrote - and --password-file - both want stdin; put the \
             password in a file",
        ));
    }

    let (text, source) = if wrote == stdin {
        let mut text = String::new();
        io::stdin().read_to_string(&mut text)?;
        (text, "stdin".to_owned())
    } else {
        let text = std::fs::read_to_string(wrote)
            .map_err(|error| Failure::error(format!("{}: {error}", wrote.display())))?;
        (text, wrote.display().to_string())
    };
    let statement: wrote::Statement = text.parse().map_err(|error| {
        Failure::error(format!(
            "{source} is not a statement this build can read, so nothing was \
             signed: {error}"
        ))
    })?;
    let revisions: Vec<RevisionId> = statement
        .lines()
        .filter_map(|line| match line {
            Line::Revision(id) => Some(*id),
            Line::Name(_) | Line::Unname(_) | Line::Gone(_) => None,
        })
        .collect();
    if revisions.is_empty() {
        // Before the store or the key: a wrapper that pipes every command
        // here should cost nothing, and ask nothing, when one wrote nothing.
        return printing(|out| {
            writeln!(
                out,
                "{source} names no revision written, so there is nothing to vouch for"
            )
        });
    }

    let store = open(base)?;
    if let Some(missing) = revisions.iter().find(|id| !store.holds(id)) {
        return Err(Failure::error(format!(
            "{source} names {}, which this store does not hold, so nothing was \
             signed",
            missing.abbreviate(12)
        )));
    }

    let secret = secret_key(key_path, password_file.as_deref())?;
    let mut filed = Vec::with_capacity(revisions.len());
    for revision in revisions {
        // One at a time, each seeing the ones before it filed: the name a
        // claim takes depends on what is already there.
        filed.push(file_claim(&store, revision, None, role.clone(), &secret)?);
    }
    printing(|out| {
        for (index, filed) in filed.iter().enumerate() {
            if index > 0 {
                writeln!(out)?;
            }
            filed.print(out)?;
        }
        // One key signed them all, so one line says who it is.
        match filed.iter().find(|filed| !filed.held) {
            Some(filed) => filed.who(out),
            None => Ok(()),
        }
    })
}

/// A claim this command vouched with, and where it is filed.
struct Filed {
    claim: Claim,
    subject: String,
    /// The claim and signature files, or the one file already holding it.
    paths: Vec<PathBuf>,
    /// Whether the store already held this claim, unchanged.
    already: bool,
    /// Whether it held it before this command looked, under whatever name,
    /// so that nothing was written and there is no key to introduce.
    held: bool,
    known: Option<String>,
}

impl Filed {
    fn print(&self, out: &mut dyn Write) -> io::Result<()> {
        let claim = &self.claim;
        writeln!(
            out,
            "{} vouches for {} as {}",
            claim.key, self.subject, claim.role
        )?;
        for path in &self.paths {
            writeln!(out, "  {}", path.display())?;
        }
        if self.already {
            writeln!(out, "\nthis store already held that claim, unchanged")?;
        }
        Ok(())
    }

    /// Who this copy takes the signing key to be, or how to say. Nothing,
    /// for a claim that was already held.
    fn who(&self, out: &mut dyn Write) -> io::Result<()> {
        if self.held {
            return Ok(());
        }
        match &self.known {
            Some(who) => writeln!(out, "\nthis copy takes that key to be {who}"),
            None => writeln!(
                out,
                "\nnothing in trust/ speaks for that key, so `verify` here will \
                 note the claim rather than count it:\n  historica-minisign \
                 trust add {} \"Your Name <you@example.com>\"",
                self.claim.key
            ),
        }
    }
}

/// Sign one claim over `revision` — or over one file at it — and file it,
/// unless the store already holds it under any name.
fn file_claim(
    store: &Store,
    revision: RevisionId,
    one_file: Option<(String, ContentDigest)>,
    role: Role,
    secret: &sign::SecretKey,
) -> Result<Filed, Failure> {
    let (claim, path_in_tree) = match one_file {
        None => (
            sign::claim_for(revision, role, secret, &Platform).map_err(Failure::error)?,
            None,
        ),
        Some((spelling, content)) => {
            let (file, path) = file_at(store, &revision, &spelling)?;
            let claim = sign::file_claim_for(revision, file, content, role, secret, &Platform)
                .map_err(Failure::error)?;
            (claim, Some(path))
        }
    };
    let subject = subject(&claim, path_in_tree.as_deref());
    let policy = trust::Trust::read(store.filesystem(), store.root())?;
    let known = policy.who(&claim.key).map(str::to_owned);

    // What is already filed decides two things: whether this claim is here
    // under any name at all, and which of decision 0003's collision tiers its
    // own name takes.
    let report = verify::verify(store)?;
    if let Some(held) = report.held().iter().find(|held| held.claim == claim) {
        let path = held.path.clone();
        return Ok(Filed {
            claim,
            subject,
            paths: vec![path],
            already: true,
            held: true,
            known,
        });
    }

    let existing: Vec<(RevisionId, Claim)> = report
        .held()
        .iter()
        .map(|held| (held.claim.digest(), held.claim.clone()))
        .collect();
    let stem = naming::stem_for(
        &claim.digest(),
        &claim,
        store.documents()?,
        existing.iter().map(|(digest, claim)| (digest, claim)),
    );

    let written = sign::write(store.filesystem(), store.root(), &claim, &stem, secret)
        .map_err(Failure::error)?;
    Ok(Filed {
        claim,
        subject,
        paths: vec![written.claim, written.signature],
        already: written.already,
        held: false,
        known,
    })
}

/// The file `spelling` names at `revision`: a path in that revision's tree,
/// or failing that a file ID it holds. Refused if it is neither, because the
/// claim would be one `verify` calls an error.
fn file_at(
    store: &Store,
    revision: &RevisionId,
    spelling: &str,
) -> Result<(FileId, String), Failure> {
    let tree = store.tree(revision).map_err(|error| {
        Failure::error(format!(
            "the files at {} cannot be read, so no file there can be vouched \
             for: {error}",
            revision.abbreviate(12)
        ))
    })?;
    match tree.at(spelling).as_slice() {
        [file] => return Ok((*file, spelling.to_owned())),
        [] => {}
        _ => {
            return Err(Failure::error(format!(
                "{} holds more than one file at {spelling}; name the one you \
                 mean by its file ID",
                revision.abbreviate(12)
            )));
        }
    }
    let unheld = || {
        Failure::error(format!(
            "{} holds no file at {spelling}, nor one with that ID",
            revision.abbreviate(12)
        ))
    };
    let file: FileId = spelling.parse().map_err(|_| unheld())?;
    match verify::find_file(store, revision, &file) {
        FileCheck::Found { path } => Ok((file, path)),
        _ => Err(unheld()),
    }
}

/// What a claim vouches for, as one phrase: a revision, or a file at one.
fn subject(claim: &Claim, path: Option<&str>) -> String {
    let revision = claim.revision.abbreviate(12);
    match claim.file() {
        None => revision,
        Some((file, content)) => format!(
            "{} ({}) at {revision}, content {content},",
            path.unwrap_or("a file"),
            file.abbreviate(naming::FILE_CHARS)
        ),
    }
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn verify_command(base: &Path, arguments: &[String]) -> Result<u8, Failure> {
    let mut spelling: Option<String> = None;
    let mut complete = false;

    for argument in arguments {
        match argument.as_str() {
            "--complete" => complete = true,
            other if other.starts_with("--") => {
                return Err(Failure::usage(format!(
                    "`{other}` is not an option to verify"
                )));
            }
            other if spelling.is_none() => spelling = Some(other.to_owned()),
            other => {
                return Err(Failure::usage(format!(
                    "`{other}`: verify asks about one revision"
                )));
            }
        }
    }

    let store = open(base)?;
    let asked = match spelling.as_deref() {
        Some(spelling) => Some(target::resolve(&store, spelling)?),
        None => None,
    };
    let report = verify::verify(&store)?;

    let counted = report.held().iter().filter(|held| held.counts()).count();
    printing(|out| {
        writeln!(
            out,
            "{} claim{}, {counted} by a key this copy believes",
            report.held().len(),
            if report.held().len() == 1 { "" } else { "s" }
        )?;
        for held in report.held() {
            let who = held
                .who
                .clone()
                .unwrap_or_else(|| "a key this copy does not hold".to_owned());
            let path = match &held.file {
                FileCheck::Found { path } => Some(path.as_str()),
                _ => None,
            };
            writeln!(
                out,
                "  {} as {} by {who}{}",
                subject(&held.claim, path),
                held.claim.role,
                if held.verified { "" } else { " — UNVERIFIED" }
            )?;
        }

        if !report.statements().is_empty() {
            let believed = report
                .statements()
                .iter()
                .filter(|held| held.counts())
                .count();
            writeln!(
                out,
                "\n{} head statement{}, {believed} by a key this copy believes",
                report.statements().len(),
                if report.statements().len() == 1 {
                    ""
                } else {
                    "s"
                }
            )?;
            for (_, held) in report.latest() {
                let heads = held.statement.heads.len();
                writeln!(
                    out,
                    "  {} at count {}, {heads} head{}{}",
                    held.who
                        .as_deref()
                        .unwrap_or("a key this copy does not hold"),
                    held.statement.counter,
                    if heads == 1 { "" } else { "s" },
                    match report.seen().get(&held.statement.key) {
                        Some(seen) => format!(", seen here at {}", seen.counter),
                        None => String::new(),
                    }
                )?;
            }
        }

        if let Some(revision) = asked {
            writeln!(
                out,
                "\n{} is {}",
                revision.abbreviate(12),
                if report.vouches_for(&revision) {
                    "vouched for"
                } else {
                    "vouched for by nobody this copy believes"
                }
            )?;
        } else {
            writeln!(
                out,
                "\n{} of {} revisions are vouched for",
                report.vouched().len(),
                report.revisions()
            )?;
        }
        let files = report.vouched_files().count();
        if files > 0 {
            writeln!(
                out,
                "{files} {} over one file, each for that file's content alone",
                if files == 1 {
                    "claim counts"
                } else {
                    "claims count"
                }
            )?;
        }

        say(out, &report, Severity::Error, "errors")?;
        say(out, &report, Severity::Note, "notes")?;
        Ok(())
    })?;

    let asked_and_unvouched = asked.is_some_and(|revision| !report.vouches_for(&revision));
    let ok = if complete {
        report.complete() && !asked_and_unvouched
    } else {
        report.ok() && !asked_and_unvouched
    };
    Ok(if ok { 0 } else { 1 })
}

// ---------------------------------------------------------------------------
// state and witness
// ---------------------------------------------------------------------------

/// Write a head statement over every head this store has. Decision 0005.
fn state_command(base: &Path, arguments: &[String]) -> Result<u8, Failure> {
    let mut key_path: Option<PathBuf> = None;
    let mut password_file: Option<PathBuf> = None;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--key" => key_path = Some(PathBuf::from(value(&mut rest, "--key")?)),
            "--password-file" => {
                password_file = Some(PathBuf::from(value(&mut rest, "--password-file")?));
            }
            other => {
                return Err(Failure::usage(format!(
                    "`{other}`: state takes no target, because it states every head"
                )));
            }
        }
    }

    let store = open(base)?;
    let secret = secret_key(key_path, password_file.as_deref())?;
    let key = sign::public_key(&secret).map_err(Failure::error)?;

    let report = verify::verify(&store)?;
    let counter = match report.highest_counter(&key) {
        None => 1,
        Some(highest) => highest.checked_add(1).ok_or_else(|| {
            Failure::error("this key has stated as many times as a count can hold")
        })?,
    };
    let statement = sign::statement_for(store.history().heads(), counter, &secret, &Platform)
        .map_err(Failure::error)?;
    let existing: Vec<(RevisionId, historica_minisign::Statement)> = report
        .statements()
        .iter()
        .map(|held| (held.statement.digest(), held.statement.clone()))
        .collect();
    let stem = naming::statement_stem(
        &statement.digest(),
        &statement,
        existing
            .iter()
            .map(|(digest, statement)| (digest, statement)),
    );
    let written =
        sign::write_statement(store.filesystem(), store.root(), &statement, &stem, &secret)
            .map_err(Failure::error)?;

    let heads = statement.heads.len();
    printing(|out| {
        writeln!(
            out,
            "{} states {heads} head{} at count {counter}",
            statement.key,
            if heads == 1 { "" } else { "s" }
        )?;
        writeln!(out, "  {}", written.claim.display())?;
        writeln!(out, "  {}", written.signature.display())
    })
}

/// Raise this copy's record of what it has seen. Decision 0005.
fn witness_command(base: &Path, arguments: &[String]) -> Result<u8, Failure> {
    if let Some(argument) = arguments.first() {
        return Err(Failure::usage(format!(
            "`{argument}`: witness takes nothing"
        )));
    }
    let store = open(base)?;
    let report = verify::verify(&store)?;
    let written = seen::witness(store.filesystem(), store.root(), &report)?;
    printing(|out| {
        if written.is_empty() {
            writeln!(out, "nothing newer to witness")?;
        }
        for record in &written {
            writeln!(
                out,
                "this copy has now seen {} at count {}",
                record.key, record.counter
            )?;
        }
        say(out, &report, Severity::Error, "errors")
    })?;
    Ok(if report.ok() { 0 } else { 1 })
}

fn say(
    out: &mut dyn Write,
    report: &verify::Report,
    severity: Severity,
    heading: &str,
) -> io::Result<()> {
    let findings: Vec<&Finding> = report
        .findings()
        .filter(|finding| finding.severity() == severity)
        .collect();
    if findings.is_empty() {
        return Ok(());
    }
    writeln!(out, "\n{heading}:")?;
    for finding in findings {
        writeln!(out, "  - {finding}")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// arrange
// ---------------------------------------------------------------------------

/// Re-file every claim under the name this tool would choose for it.
///
/// Historica's decision 0019, inherited whole: only `arrange` renames, because
/// a writer names the file it is creating rather than renaming it afterwards.
/// So a rename here is always presentation being tidied and never a document
/// being written — and a claim's bytes are untouched by all of it, which is why
/// its signature is still valid afterwards.
fn arrange_command(base: &Path, arguments: &[String]) -> Result<u8, Failure> {
    let mut dry_run = false;
    let mut prune = false;
    for argument in arguments {
        match argument.as_str() {
            "--dry-run" => dry_run = true,
            "--prune" => prune = true,
            other => {
                return Err(Failure::usage(format!(
                    "`{other}` is not an option to arrange"
                )));
            }
        }
    }

    let store = open(base)?;
    let files = store.filesystem();
    let root = store.root();
    let report = verify::verify(&store)?;

    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut taken: Vec<PathBuf> = Vec::new();
    let mut pruned: Vec<PathBuf> = Vec::new();
    let mut left: Vec<PathBuf> = Vec::new();

    for finding in report.findings() {
        match finding {
            Finding::Misfiled { path, should_be } => {
                let stem = should_be.strip_suffix(CLAIM_SUFFIX).unwrap_or(should_be);
                let to = claim_file(root, stem);
                // Decision 0019's rule for a destination that is occupied:
                // look before moving, and leave a name that is taken.
                if files.look(&to)?.is_some() {
                    taken.push(path.clone());
                    continue;
                }
                if !dry_run {
                    let directory = to.parent().unwrap_or(root).to_path_buf();
                    files.create_directory(&directory)?;
                    files.rename(path, &to)?;
                    // The signature goes with the claim it signs, or it becomes
                    // an orphan and the claim becomes unsigned — which is the
                    // one note in this design that is an error.
                    let signature = beside(path);
                    if files.look(&signature)?.is_some() {
                        files.rename(&signature, &signature_file(root, stem))?;
                    }
                    tidy(&store, path)?;
                }
                moved.push((path.clone(), to));
            }
            Finding::Duplicate { path, of } => {
                if !prune {
                    left.push(path.clone());
                    continue;
                }
                // The bytes, compared, immediately before deleting anything.
                // The digests already matched or this would not be a duplicate;
                // reading both again costs one file and buys the guarantee that
                // what is deleted is a copy of something still here.
                if files.read(path)? != files.read(of)? {
                    left.push(path.clone());
                    continue;
                }
                if !dry_run {
                    let signature = beside(path);
                    if files.look(&signature)?.is_some() {
                        files.remove_file(&signature)?;
                    }
                    files.remove_file(path)?;
                    tidy(&store, path)?;
                }
                pruned.push(path.clone());
            }
            _ => {}
        }
    }

    printing(|out| {
        if moved.is_empty() && pruned.is_empty() && taken.is_empty() && left.is_empty() {
            return writeln!(out, "every claim is filed where it belongs");
        }
        let verb = if dry_run { "would move" } else { "moved" };
        for (from, to) in &moved {
            writeln!(out, "{verb} {}", from.display())?;
            writeln!(out, "     to {}", to.display())?;
        }
        for path in &pruned {
            writeln!(
                out,
                "{} {}",
                if dry_run { "would delete" } else { "deleted" },
                path.display()
            )?;
        }
        for path in &taken {
            writeln!(
                out,
                "left {}: the name it belongs under is taken by something else",
                path.display()
            )?;
        }
        for path in &left {
            writeln!(
                out,
                "left {}: a duplicate, which --prune deletes",
                path.display()
            )?;
        }
        Ok(())
    })
}

/// The signature that sits beside a claim.
fn beside(claim: &Path) -> PathBuf {
    let mut path = claim.to_path_buf();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();
    path.set_file_name(format!("{name}{SIGNATURE_SUFFIX}"));
    path
}

/// Remove the directories a move emptied, upwards, stopping at the first that
/// still holds something.
///
/// Historica's rule, and the refusal is the feature: a directory that is not
/// empty says so, which is the only reason walking upwards is a correct stop.
/// `claims/` itself is never removed — an empty claims directory is a store
/// nobody has vouched for, which is a thing a store is allowed to be.
fn tidy(store: &Store, from: &Path) -> Result<(), Failure> {
    let ceiling = claims(store.root());
    let mut directory = from.parent().map(Path::to_path_buf);
    while let Some(path) = directory {
        if path == ceiling || !path.starts_with(&ceiling) {
            break;
        }
        if store.filesystem().remove_directory(&path).is_err() {
            break;
        }
        directory = path.parent().map(Path::to_path_buf);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// trust
// ---------------------------------------------------------------------------

fn trust_command(base: &Path, arguments: &[String]) -> Result<u8, Failure> {
    let (verb, rest) = arguments
        .split_first()
        .ok_or_else(|| Failure::usage("trust wants `add`, `list`, `remove`, or `revoke`"))?;

    match verb.as_str() {
        "list" => trust_list(base, rest),
        "add" => trust_add(base, rest),
        "remove" => trust_remove(base, rest),
        "revoke" => trust_revoke(base, rest),
        other => Err(Failure::usage(format!(
            "`{other}`: trust wants `add`, `list`, `remove`, or `revoke`"
        ))),
    }
}

fn trust_list(base: &Path, arguments: &[String]) -> Result<u8, Failure> {
    if let Some(extra) = arguments.first() {
        return Err(Failure::usage(format!(
            "`{extra}`: trust list takes nothing"
        )));
    }
    let store = open(base)?;
    let policy = trust::Trust::read(store.filesystem(), store.root())?;

    printing(|out| {
        if policy.is_empty() {
            writeln!(
                out,
                "this copy believes nobody yet; `historica-minisign trust add \
                 <key> <who>` is how it starts"
            )?;
        }
        for (label, entry) in policy.entries() {
            writeln!(out, "{label}  {}", entry.who)?;
            writeln!(out, "  {}", entry.key)?;
            if let Some(added) = &entry.added {
                writeln!(out, "  added {added}")?;
            }
            if let Some(revoked) = &entry.revoked {
                writeln!(out, "  revoked {revoked}")?;
            }
        }
        for (path, because) in policy.malformed() {
            writeln!(out, "\n{} is not an entry: {because}", path.display())?;
        }
        Ok(())
    })
}

fn trust_add(base: &Path, arguments: &[String]) -> Result<u8, Failure> {
    let mut key_text: Option<String> = None;
    let mut who: Option<String> = None;
    let mut label: Option<String> = None;

    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--label" => label = Some(value(&mut rest, "--label")?),
            other if other.starts_with("--") => {
                return Err(Failure::usage(format!(
                    "`{other}` is not an option to trust add"
                )));
            }
            other if key_text.is_none() => key_text = Some(other.to_owned()),
            other if who.is_none() => who = Some(other.to_owned()),
            other => {
                return Err(Failure::usage(format!(
                    "`{other}`: trust add takes one key and one person"
                )));
            }
        }
    }

    let key_text = key_text.ok_or_else(|| Failure::usage("trust add wants a key"))?;
    let who = who.ok_or_else(|| {
        Failure::usage("trust add wants who that key speaks for, as text you will recognise")
    })?;
    let key: Key = key_text
        .parse()
        .map_err(|error| Failure::usage(format!("{error}")))?;

    // A label nobody chose is who the key speaks for; see
    // `trust::default_label`.
    let chosen = label.is_some();
    let label = label.unwrap_or_else(|| trust::default_label(&key, &who));
    if !trust::is_a_label(&label) {
        return Err(Failure::usage(format!(
            "`{label}` is not one filename, and a label is: it holds no `/`, \
             and is not empty, `.`, or `..`"
        )));
    }

    let store = open(base)?;
    let entry = trust::Entry::new(key.clone(), who.clone());
    let path = match trust::add(store.filesystem(), store.root(), &label, &entry) {
        Ok(path) => path,
        // One person with two keys lands on one name. A label the tool chose is
        // the tool's to make unambiguous; a label somebody typed is theirs, and
        // being told it is taken is the right answer.
        Err(trust::TrustError::Taken { .. }) if !chosen => {
            let label = format!("{label} {}", naming::key_prefix(&key));
            trust::add(store.filesystem(), store.root(), &label, &entry).map_err(Failure::error)?
        }
        Err(error) => return Err(Failure::error(error)),
    };

    printing(|out| {
        writeln!(out, "this copy now takes {key} to be {who}")?;
        writeln!(out, "  {}", path.display())?;
        writeln!(
            out,
            "\nthis file stays here: no receive, export, or sync of a store \
             carries an opinion about who to believe"
        )
    })
}

fn trust_remove(base: &Path, arguments: &[String]) -> Result<u8, Failure> {
    let [label] = arguments else {
        return Err(Failure::usage("trust remove wants one label"));
    };
    let store = open(base)?;
    let path = trust::remove(store.filesystem(), store.root(), label).map_err(Failure::error)?;
    printing(|out| writeln!(out, "removed {}", path.display()))
}

fn trust_revoke(base: &Path, arguments: &[String]) -> Result<u8, Failure> {
    let mut label: Option<String> = None;
    let mut as_of: Option<String> = None;

    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--as-of" => as_of = Some(value(&mut rest, "--as-of")?),
            other if other.starts_with("--") => {
                return Err(Failure::usage(format!(
                    "`{other}` is not an option to trust revoke"
                )));
            }
            other if label.is_none() => label = Some(other.to_owned()),
            other => {
                return Err(Failure::usage(format!(
                    "`{other}`: trust revoke takes one label"
                )));
            }
        }
    }
    let label = label.ok_or_else(|| Failure::usage("trust revoke wants one label"))?;
    let when: Timestamp = match as_of {
        Some(text) => text
            .parse()
            .map_err(|error| Failure::usage(format!("`{text}`: {error}")))?,
        None => Platform.now().map_err(|error| {
            Failure::error(format!("the clock could not say when now is: {error}"))
        })?,
    };

    let store = open(base)?;
    let (path, entry) =
        trust::revoke(store.filesystem(), store.root(), &label, &when).map_err(Failure::error)?;
    let revoked = entry.revoked.as_ref().unwrap_or(&when);

    printing(|out| {
        writeln!(out, "{} is revoked as of {revoked}", entry.key)?;
        writeln!(out, "  {}", path.display())?;
        if revoked != &when {
            writeln!(
                out,
                "\nit was already revoked as of that earlier time, which stands: \
                 a revocation only moves earlier"
            )?;
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// key
// ---------------------------------------------------------------------------

fn key_command(arguments: &[String]) -> Result<u8, Failure> {
    let (verb, rest) = arguments
        .split_first()
        .ok_or_else(|| Failure::usage("key wants `new` or `show`"))?;

    match verb.as_str() {
        "new" => key_new(rest),
        "show" => key_show(rest),
        other => Err(Failure::usage(format!(
            "`{other}`: key wants `new` or `show`"
        ))),
    }
}

fn key_new(arguments: &[String]) -> Result<u8, Failure> {
    let mut at: Option<PathBuf> = None;
    let mut password_file: Option<PathBuf> = None;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--at" => at = Some(PathBuf::from(value(&mut rest, "--at")?)),
            "--password-file" => {
                password_file = Some(PathBuf::from(value(&mut rest, "--password-file")?));
            }
            other => {
                return Err(Failure::usage(format!(
                    "`{other}` is not an option to key new"
                )));
            }
        }
    }

    let directory = match at {
        Some(at) => at,
        None => key::default_secret_key()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .ok_or_else(|| {
                Failure::error(
                    "this platform will not say where home is; name a \
                     directory with --at",
                )
            })?,
    };

    let generated =
        key::generate(&directory, password(password_file.as_deref())?).map_err(Failure::error)?;
    printing(|out| {
        writeln!(out, "{}", generated.key)?;
        writeln!(out, "  secret  {}", generated.secret.display())?;
        writeln!(out, "  public  {}", generated.public.display())?;
        writeln!(
            out,
            "\nthe secret key is the only thing here that cannot be replaced: \
             back it up, and nothing else needs to be. Tell a store to believe \
             it with\n  historica-minisign trust add {} \"Your Name \
             <you@example.com>\"",
            generated.key
        )
    })
}

fn key_show(arguments: &[String]) -> Result<u8, Failure> {
    let mut path: Option<PathBuf> = None;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--public" => path = Some(PathBuf::from(value(&mut rest, "--public")?)),
            other => {
                return Err(Failure::usage(format!(
                    "`{other}` is not an option to key show"
                )));
            }
        }
    }

    let path = match path {
        Some(path) => path,
        None => key::default_secret_key()
            .and_then(|secret| secret.parent().map(|dir| dir.join(key::PUBLIC_KEY_FILE)))
            .ok_or_else(|| {
                Failure::error(
                    "this platform will not say where home is; name a file \
                     with --public",
                )
            })?,
    };

    let text = std::fs::read_to_string(&path)
        .map_err(|error| Failure::error(format!("{}: {error}", path.display())))?;
    // The public key file is two lines and the second is the key. Parsed
    // rather than printed blind, so this never hands somebody a line that
    // `trust add` will refuse.
    let line = text
        .lines()
        .find_map(|line| line.trim().parse::<Key>().ok())
        .ok_or_else(|| {
            Failure::error(format!("{} holds no minisign public key", path.display()))
        })?;
    printing(|out| writeln!(out, "{line}"))
}

// ---------------------------------------------------------------------------
// The small shared things
// ---------------------------------------------------------------------------

/// The store containing `base`, found by walking up, as `historica` does it.
fn open(base: &Path) -> Result<Store, Failure> {
    Store::discover(base).map_err(Failure::from)
}

/// The secret key at `path`, or at minisign's default where none was named,
/// unlocked with the password in `password_file` or asked for at a terminal.
fn secret_key(
    path: Option<PathBuf>,
    password_file: Option<&Path>,
) -> Result<sign::SecretKey, Failure> {
    let path = match path {
        Some(path) => path,
        None => key::default_secret_key().ok_or_else(|| {
            Failure::error(
                "this platform will not say where home is, so there is no \
                 default key; name one with --key",
            )
        })?,
    };
    let password = password(password_file)?;
    key::load(&path, password).map_err(Failure::error)
}

/// The password to unlock or protect a key with, or `None` to ask a terminal.
fn password(from: Option<&Path>) -> Result<Option<String>, Failure> {
    from.map(key::password_from)
        .transpose()
        .map_err(Failure::error)
}

fn value<'a>(
    arguments: &mut impl Iterator<Item = &'a String>,
    option: &str,
) -> Result<String, Failure> {
    arguments
        .next()
        .map(String::to_owned)
        .ok_or_else(|| Failure::usage(format!("`{option}` wants a value")))
}

/// Write to stdout, treating a closed pipe as the ordinary end of a command
/// rather than as a fault: `historica-minisign verify | head` should not report
/// an error about the reader that stopped reading.
fn printing(write: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> Result<u8, Failure> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match write(&mut out).and_then(|()| out.flush()) {
        Ok(()) => Ok(0),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(0),
        Err(error) => Err(Failure::error(error)),
    }
}
