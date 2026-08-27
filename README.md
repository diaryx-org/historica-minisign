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

**Head statements are not built.** 0046 specifies a second document kind — a
key, a counter, and the heads its history had at that moment — which is what
detects a store presenting a subset of a history it has already shown you.
Nothing here detects a withheld revision, and it does not pretend to.

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

named by the SHA-256 of its own bytes, with an ordinary detached minisign
signature beside it. Anything this tool can write, `minisign -Sm` can write;
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

`historica-minisign` depends on historica with both a version and a path, so it
builds only with historica checked out beside it, and cannot be published until
historica is.

```console
$ cargo xtask ci
```

is every CI job, in the order CI runs them.

## Licence

MIT or Apache-2.0, at your option.
