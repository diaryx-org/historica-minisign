# historica-minisign

Who vouches for a revision in a [Historica](https://github.com/diaryx-org/historica)
store.

Every Historica revision states an `author`, and nothing checks it. The digests
answer *whether these are the bytes*; they say nothing about *whose word they
are*. A history fabricated under somebody else's name, with every digest
correct, passes every gate the format has.

This is the tool that closes that, from outside. It writes a **claim** — one
key vouching for one revision digest, in one role, at one moment — signs it with
[minisign](https://jedisct1.github.io/minisign/), and puts both files in
`history/claims/`. Which keys a copy of the store believes is a directory of
text files in `history/trust/`, and that directory never travels.

Historica gains no command, no cryptographic dependency, and no grammar. Its
[decision 0046](https://github.com/diaryx-org/historica/blob/main/docs/decisions/0046-who-vouches-for-a-revision.md)
is where all of this is argued and where the boundary is fixed; this repository
fills in the grammar, and nothing more.

## Status

Claims, trust, and verification work end to end.

```console
$ historica-minisign key new
RWQq6vJVR0z0KLGfXKp1a2mYlUB0kUZC8oXbEPu29z1DnKUB0FdrRhJs
  secret  /Users/adam/.minisign/minisign.key
  public  /Users/adam/.minisign/minisign.pub

$ historica-minisign sign --role reviewer
RWQq6vJVR0z0KLGfXKp1a2mYlUB0kUZC8oXbEPu29z1DnKUB0FdrRhJs vouches for 3d0f1b2c9a44 as reviewer
  history/claims/8c1e….claim.txt
  history/claims/8c1e….claim.txt.minisig

$ historica-minisign trust add RWQq6vJ… "Adam Harris <adam@example.com>"
$ historica-minisign verify --complete
1 claim, 1 by a key this copy believes
  3d0f1b2c9a44 as reviewer by Adam Harris <adam@example.com>

12 of 12 revisions are vouched for
```

One claim over one revision covers everything that revision descends from — a
digest pins its bytes, which pin its parents' digests, and so on to the roots —
so signing the head signs the history behind it, and signing every revision is
a choice rather than a requirement.

What it is meant to sign is what a `historica` command just wrote. Run with
`--fields`, a writing command prints a `historica-wrote-1` statement of what it
wrote ([historica's decision 0074](https://github.com/diaryx-org/historica/blob/main/docs/decisions/0074-saying-where-to-look.md)),
and `sign --wrote -` signs every revision that statement names:

```console
$ historica record --fields -m 'note' | historica-minisign sign --wrote -
RWQq6vJVR0z0KLGfXKp1a2mYlUB0kUZC8oXbEPu29z1DnKUB0FdrRhJs vouches for 2160886dffb6 as author
  history/claims/2026-10/2026-10-21 note — author.claim.txt
  history/claims/2026-10/2026-10-21 note — author.claim.txt.minisig
```

So signing every capture is a one-line alias. A command that wrote nothing
says so, and then nothing is signed and nothing is asked for; a statement this
build cannot read is refused whole, and nothing is signed either.

A claim can also be narrower: one file as it stood at a revision, naming that
file's content digest, which is what a reviewer who read one document can
honestly sign.

```console
$ historica-minisign sign --role reviewer --file notes.md --content sha256:9f86d0…
```

It is written as `claim-1`, covers that file alone, neither the revision nor
its history, and keeps standing for as long as the file's content digest now
is the one it names. Comparing the two is the job of whatever tool computed the
digest. This one records it and never computes it.
[Decision 0004](docs/decisions/0004-a-claim-can-be-over-one-file.md) has the
grammar and the argument.

A claim can also be over one document that is not a revision, such as a
forgetting, which no revision names and so nobody could otherwise sign. It is
written as `claim-2`, names the document's digest, and vouches for no
revision.
[Decision 0006](docs/decisions/0006-a-claim-can-be-over-one-document.md) has
the grammar and the argument.

**Head statements** answer the subset a set of claims cannot. A key states,
at a count that only goes up, every head its history had:

```console
$ historica-minisign state
RWQq6vJ… states 1 head at count 3
  history/claims/heads/8c1e4a2f/3.heads.txt
  history/claims/heads/8c1e4a2f/3.heads.txt.minisig

$ historica-minisign witness
this copy has now seen RWQq6vJ… at count 3
```

From then on `verify` refuses a store that holds less than a believed key's
latest statement names, one where that key stated two things at one count,
and one rolled back below what this copy has witnessed. What a copy has
witnessed is kept in `history/trust/seen/` and never travels.
[Decision 0005](docs/decisions/0005-a-key-states-its-heads.md) has the grammar
and the argument. A newer statement that was never shown cannot be detected,
and nothing here pretends otherwise.

**A key has a history.** A person holds a key for each device, and a lost one
is revoked as of a time they name. Its claims from before that time still
count, and later ones do not:

```console
$ historica-minisign trust revoke laptop --as-of 2026-10-19T08:30:00-06:00
RWQq6vJ… is revoked as of 2026-10-19T08:30:00-06:00
  history/trust/laptop.txt
```

**A copy can follow what keys vouched for.** `Vouched` is a rule for
Historica's [decision 0086](https://github.com/diaryx-org/historica/blob/main/docs/decisions/0086-a-copy-chooses-its-heads.md):
it accepts a revision that a claim by one of its keys vouches for, so a copy's
heads are the lines those keys signed.
[Decision 0007](docs/decisions/0007-a-key-has-a-history.md) has both.

## Reading with a device key

Historica's fetch sends nothing about who is asking. A server that keeps a
copy to its members can ask for the same key that signs claims instead:

```console
$ historica minisign fetch https://hub.example.org/adam/notes/offer.txt
$ historica minisign token https://hub.example.org
{"token":"…","expires":"2026-10-20T18:05:00Z"}
```

`fetch` is `historica fetch`, with every request signed:
`Authorization: Minisign <key-id> <time> <signature>`, over the method, host,
path and time. A server takes it within five minutes of its own clock, so a
copied header reads one path, for minutes. `token` gets a short-lived token
for `git clone`, which cannot sign. The grammar, the window, and the token
contract are in the `request` and `http` modules' documentation. The
`request` half needs no feature, for a server or a page that brings its own
HTTP.

## Checking a claim without this tool

Two commands, and neither is Historica nor this program:

```console
$ minisign -Vm history/claims/8c1e….claim.txt -P RWQq6vJ…
$ shasum -a 256 history/revisions/2026-08/3d0f….rev.txt
```

That is the point of the design rather than a nicety. A claim is five lines of
text:

```
claim-0
revision 33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a
role reviewer
key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
when 2026-08-24T09:12:04-06:00
```

A claim over one file is a `claim-1`: seven lines, with `file` and `content`
after `revision`. A claim over one document is a `claim-2`, with
`document` in place of `revision`. Either kind has an ordinary detached minisign signature
beside it. Anything this tool can write, `minisign -Sm` can write;
anything `minisign -Vm` accepts, this accepts. Tests pin both directions
against the real command.

## Two decisions everything is written under

[Decision 0001](docs/decisions/0001-a-claim-is-a-file-beside-the-history.md)
fixes the grammar 0046 left to this repository — the claim document, the trust
entry, the filenames, and what `verify` calls an error rather than an
observation. Its load-bearing half is what a reader does with a line it does
not recognise: **it refuses the document**. Historica ignores an `x-` header it
does not know, because a document it does not fully understand still states
what it states. A claim is read to answer *should I believe this*, and a header
a later grammar adds is far likelier to narrow a claim than to widen it — an
`expires`, a `scope` — so a reader that skipped what it had never seen would
accept a claim its author had already limited.

[Decision 0002](docs/decisions/0002-the-signature-is-linked-not-called.md)
links minisign rather than calling it, which is the opposite of what
historica-git decided about git, and says why: almost nobody has minisign
installed, the surface being bought is one algorithm rather than twenty years
of edge cases, and verification has to work on the machines least likely to
have anything installed.

## Trust does not travel

`history/trust/` is the one directory in this design that no operation of this
tool, and no operation of Historica, ever writes from another store.

Historica's decision 0045 lets skip rules union between stores and lets a
deleted one resurrect, on the argument that resurrection is the safe direction
of failure. Both edges of that invert for trust. A rule arriving means *record
less*, which fails closed; a trust entry arriving means *believe more*, and a
store seeded with an attacker's key verifies the attacker's history. And union
without tombstones structurally cannot make removal win, which is exactly what
revoking a compromised key requires.

What it costs: somebody with three machines states their policy three times, or
copies the directory themselves, deliberately, knowing what it is.

The line that keeps it consistent rather than exceptional: **a claim is a fact,
and trust is an opinion.** Claims union freely, because holding one commits a
store to nothing.

## Verifying without signing

`default-features = false` leaves a library that can only verify, and its whole
dependency is `minisign-verify`, which has none of its own. 0046 defers
*enforcement at receive* — a `receive` that refuses history no trusted key
vouches for — and that is the build it would take. A CI job builds it on every
push, so the promise cannot rot.

## Building it

`historica-minisign` depends on historica by version and not by path, so a
clone builds on its own — and so what this crate can reach is the published API
and nothing else, which is the boundary historica's decision 0053 promises from
the other side. Publishing it needs the historica version it names to be on
crates.io, for the same reason.

```console
$ ship ci
```

is every CI job, in the order CI runs them, from the list in
`.config/ship.figl`; [ship](https://github.com/diaryx-org/ship) is what reads
it, here and in the workflow.

## Licence

MIT or Apache-2.0, at your option.
