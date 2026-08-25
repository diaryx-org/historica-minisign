//! The command-line front end.
//!
//! Four commands, and only two of them write: `sign` writes a claim and its
//! signature into `history/claims/`, and `trust` writes and deletes files in
//! `history/trust/`. `verify` reads, and Historica's decision 0046 says so in
//! as many words. Nothing here writes a Historica document, ever.

mod target;

use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use historica::record::Platform;
use historica::store::{Store, StoreError};

use historica_sign::claim::{Key, Role};
use historica_sign::verify::{Finding, Severity};
use historica_sign::{key, sign, trust, verify};

/// What `historica-sign` with no arguments prints.
pub const USAGE: &str = "\
usage: historica-sign [-C <dir>] <command> [<arguments>]

  sign [<target>] [--role <role>] [--key <path>] [--password-file <path>]
                           vouch for a revision: write a claim into
                           history/claims/ and sign it. The role is what you
                           were doing — `author`, `reviewer`, `release`, or
                           whatever you say — and defaults to `author`. A
                           claim covers everything the revision descends
                           from, so signing the head signs the history. The
                           password is asked for at the terminal unless
                           --password-file names a file, or `-` for stdin
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
  key new [--at <dir>] [--password-file <path>]
                           write a minisign key pair, by default in
                           ~/.minisign. A key `minisign -G` wrote works here
                           unchanged, and so does this one there
  key show [--public <path>]
                           the public key line, which is what goes in a trust
                           entry and in `minisign -Vm -P`

a <target> is `head`, a bookmark, a change ID, or a revision digest; the last
two may be abbreviated to any unambiguous prefix, and their alphabets do not
overlap, so one argument accepts either.

a claim is a file, its signature is minisign's, and checking one by hand is
`minisign -Vm <claim> -P <key>` followed by `shasum -a 256` on the revision it
names.
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
            return printing(|out| out.write_all(USAGE.as_bytes()));
        };
        match argument.as_str() {
            "-C" => {
                let directory = arguments
                    .next()
                    .ok_or_else(|| Failure::usage("`-C` wants a directory"))?;
                base = Some(PathBuf::from(directory));
            }
            "-h" | "--help" | "help" => return printing(|out| out.write_all(USAGE.as_bytes())),
            "-V" | "--version" => {
                return printing(|out| {
                    writeln!(out, "historica-sign {}", env!("CARGO_PKG_VERSION"))
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
        "trust" => trust_command(&base, &rest),
        "key" => key_command(&rest),
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

    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--role" => role = value(&mut rest, "--role")?,
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

    let store = open(base)?;
    let revision = match spelling.as_deref() {
        Some(spelling) => target::resolve(&store, spelling)?,
        None => target::the_head(&store)?.ok_or_else(|| {
            Failure::error("this store holds no revisions, so there is nothing to vouch for")
        })?,
    };

    let path = match key_path {
        Some(path) => path,
        None => key::default_secret_key().ok_or_else(|| {
            Failure::error(
                "this platform will not say where home is, so there is no \
                 default key; name one with --key",
            )
        })?,
    };
    let password = password(password_file.as_deref())?;
    let secret = key::load(&path, password).map_err(Failure::error)?;

    let claim = sign::claim_for(revision, role, &secret, &Platform).map_err(Failure::error)?;
    let written =
        sign::write(store.filesystem(), store.root(), &claim, &secret).map_err(Failure::error)?;

    let policy = trust::Trust::read(store.filesystem(), store.root())?;
    let known = policy.who(&claim.key).map(str::to_owned);

    printing(|out| {
        writeln!(
            out,
            "{} vouches for {} as {}",
            claim.key,
            revision.abbreviate(12),
            claim.role
        )?;
        writeln!(out, "  {}", written.claim.display())?;
        writeln!(out, "  {}", written.signature.display())?;
        if written.already {
            writeln!(out, "\nthis store already held that claim, unchanged")?;
        }
        match known {
            Some(who) => writeln!(out, "\nthis copy takes that key to be {who}"),
            None => writeln!(
                out,
                "\nnothing in trust/ speaks for that key, so `verify` here will \
                 note the claim rather than count it:\n  historica-sign trust \
                 add {} \"Your Name <you@example.com>\"",
                claim.key
            ),
        }
    })
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
            writeln!(
                out,
                "  {} as {} by {who}{}",
                held.claim.revision.abbreviate(12),
                held.claim.role,
                if held.verified { "" } else { " — UNVERIFIED" }
            )?;
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
// trust
// ---------------------------------------------------------------------------

fn trust_command(base: &Path, arguments: &[String]) -> Result<u8, Failure> {
    let (verb, rest) = arguments
        .split_first()
        .ok_or_else(|| Failure::usage("trust wants `add`, `list`, or `remove`"))?;

    match verb.as_str() {
        "list" => trust_list(base, rest),
        "add" => trust_add(base, rest),
        "remove" => trust_remove(base, rest),
        other => Err(Failure::usage(format!(
            "`{other}`: trust wants `add`, `list`, or `remove`"
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
                "this copy believes nobody yet; `historica-sign trust add \
                 <key> <who>` is how it starts"
            )?;
        }
        for (label, entry) in policy.entries() {
            writeln!(out, "{label}  {}", entry.who)?;
            writeln!(out, "  {}", entry.key)?;
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

    // A label nobody chose is the digest of the key, which is a filename
    // whatever the key looks like; see `trust::default_label`.
    let label = label.unwrap_or_else(|| trust::default_label(&key));
    if !trust::is_a_label(&label) {
        return Err(Failure::usage(format!(
            "`{label}` is not one filename, and a label is: it holds no `/`, \
             and is not empty, `.`, or `..`"
        )));
    }

    let store = open(base)?;
    let entry = trust::Entry {
        key: key.clone(),
        who: who.clone(),
    };
    let path =
        trust::add(store.filesystem(), store.root(), &label, &entry).map_err(Failure::error)?;

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
             it with\n  historica-sign trust add {} \"Your Name \
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
/// rather than as a fault: `historica-sign verify | head` should not report an
/// error about the reader that stopped reading.
fn printing(write: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> Result<u8, Failure> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match write(&mut out).and_then(|()| out.flush()) {
        Ok(()) => Ok(0),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(0),
        Err(error) => Err(Failure::error(error)),
    }
}
