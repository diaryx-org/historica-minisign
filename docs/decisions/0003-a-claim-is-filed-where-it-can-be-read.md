# 0003 — A claim is filed where it can be read

Decision 0001 settled what a claim says and what it is called, and it took the
second of those from Historica's decision 0046 rather than deciding it: *claims
live in `history/claims/`, immutable and digest-named*, listed among the things
0001 "may not reopen". This decision reopens it, and the amendment to 0046 that
permits it is being made in the same breath — the two documents must not
disagree in writing, and 0046's own argument is what the amendment preserves.

## The tension this resolves

Historica's decision 0003 is titled *the store: content is identity, names are
presentation*, and its opening paragraph is a description of what `claims/`
became:

> A content-addressed store seems to want every file named by its own digest,
> and a folder of `1e4e224e….rev` is a ledger, not a story: `ls` shows nothing,
> order is invisible, and nobody hand-authors a file whose name is its own
> hash.

Every clause of that is true of a claims directory, and the last one is true of
it in a way it is not true of a revision. A revision document is written by
`historica record`; nobody was ever going to hand-author one, and readable
names are a courtesy to whoever opens the folder. A claim is different in kind.
This tool is a convenience layer over a file format and two commands that are
not this tool — that is the whole of decision 0002 — and the format is meant to
be usable by someone who has minisign and a text editor and nothing else. For
that person the digest name is not a cosmetic problem. It is a wall:

```console
$ $EDITOR /tmp/claim.txt                                  # write five lines
$ shasum -a 256 /tmp/claim.txt                            # hash what you wrote
$ mv /tmp/claim.txt "history/claims/d956de….claim.txt"    # now it can be named
$ minisign -Sm "history/claims/d956de….claim.txt"
```

The file cannot be named until after it has been written, because its name is
its content. A person who writes the five lines in the obvious place under the
obvious name has produced a file this tool reports as `Foreign` — a **note**,
not an error — and their store's coverage silently does not change. The
cheapest possible attack on this design was named in 0001 as an unsigned claim
nobody notices; this is its clumsy twin, a *signed* claim nobody counts, and
the person it happens to is the one who took the format at its word.

So the digest name defeats the purpose of the format being a format. That is
the case for reopening; what follows is the case that nothing is lost by it.

## What the digest name actually bought

0046 gave one argument, and it is about concurrency rather than integrity:

> Immutable digest-named files are the concurrency story 0003 counts on: any
> file sync unions them without conflict, and `cp -r` — the transport 0029
> declines to replace — carries them correctly.

That argument is sound and this decision keeps every word of its conclusion.
What it does not require is the *digest*. It requires that a claim's path be a
deterministic function of the claim, so two replicas that independently hold
one claim hold it at one path. Historica's revisions are readable-named,
deterministic, and travel through the same `cp -r` without conflict; decisions
0006, 0019 and 0041 are the rule that makes that work, and `naming.rs` states
the standard those names are held to:

> The one hard rule is determinism. Two replicas arranging one history must
> produce one set of filenames, or sync sees two files per document and a
> scheme meant to make a folder readable fills it with conflicted copies. That
> is why a collision appends a change ID rather than a counter: a counter
> depends on what else is in the directory, and a content-derived suffix does
> not.

A claim named by that rule is union-safe for the same reason a revision is. The
digest was one way to be deterministic, and it was the way that made the folder
unreadable and the format unusable by hand.

The integrity property the name appears to carry, it does not carry. A claim's
bytes are covered by a detached minisign signature; bytes edited under any name
fail to verify and are reported as `Refused`. The `NameIsFalse` finding is a
cheap check that needs no cryptography, not the thing that makes tampering
visible, and 0001 never claimed otherwise.

## The decision

### Where a claim is filed

A claim is filed beside the revision it vouches for, under the stem Historica
gave that revision, with the role appended:

```text
history/claims/2026-04/2026-04-12 Initial commit — author.claim.txt
history/claims/2026-04/2026-04-12 Initial commit — author.claim.txt.minisig
history/claims/2026-08/2026-08-18 drop the private export — author.claim.txt
history/claims/2026-08/2026-08-18 drop the private export — reviewer.claim.txt
```

The stem is Historica's own — `naming::stems` over the store's documents —
which brings 0041's month directory, 0006's date and sixty-character summary
cut at a word boundary, and every collision rule those decisions already
settled. Claims sort as revisions sort, file where revisions file, and a claim
signed years late lands beside the work it vouches for rather than in the month
somebody got round to it. That last property is the one worth naming: signing
an old revision today is the normal case for this tool, not the edge, and
filing by the claim's own `when` would scatter the record of a review across
the calendar of the reviewer's afternoons.

The separator is a space, an em dash, and a space. A bare space would run the
role into a summary that ends in a word, and the two would not be tellable
apart by eye — which is the only thing this scheme exists to buy.

### Where a collision goes

The three tiers of 0006, in this decision's terms, each suffix derived from
content and never from what else is in the directory:

1. `<revision stem> — <role>`.
2. Two keys vouching for one revision in one role: append the key, abbreviated
   to eight characters.
3. The same key twice in one role, differing only in `when`: append the claim's
   own digest, abbreviated to twelve.

The third tier is the digest name, arrived at from the other end — kept for the
one case where nothing else distinguishes two claims, and reached by almost
nothing. A directory of hashes was the general case and is now the last resort.

A claim naming a revision this store does not hold cannot be filed by this
rule, because the rule reads the revision. That claim is filed under its own
`when` and the revision digest it names — `2026-08/2026-08-26 author
29f2ade82644.claim.txt` — which is deterministic from the claim alone and needs
nothing this copy does not have. `Absent` was already an ordinary state, and it
stays one; `arrange` re-files the claim if the revision ever arrives.

### Identity comes from content

`verify` reads every `*.claim.txt` under `claims/`, at any depth, under any
name, and identifies each by parsing it. Two files holding one claim's bytes
are one claim, deduplicated on the digest computed at read time rather than on
the name. The name is read for exactly one purpose, which is to say whether it
is the name this scheme would have chosen.

This is the half of the change that makes the other half safe, and it is also
the half that makes a hand-written claim work. A person who writes five lines
into `claims/whatever.claim.txt` and runs `minisign -Sm` on it has made a claim
this tool counts. It will tell them where the file belongs. It will not ignore
them for having guessed wrong.

### What `verify` says about a name

A name is still a claim about the bytes under it, and this decision keeps
0001's rule that verify is what checks whether it is a true one — moved to the
layer where 0003 says names live:

- **A claim not filed under the name this scheme would choose** is a note. The
  store is intact, the claim counts in full, and `arrange` will move it. This
  is the finding that covers a hand-written claim, a claim that arrived from a
  copy which lacked the revision, and a claim whose revision's summary changed
  under an amendment.
- **A claim whose filename is a digest that is not the digest of its bytes**
  stays an error, unchanged from 0001. A digest-shaped name is a specific and
  checkable assertion, and a false one is still false.

The second is retained for the stores written before this decision, and it
costs nothing to keep: a name that is sixty-four hex characters is either
deliberate or an accident nobody will have.

The finding this decision must justify is the first one, because a readable
name introduces a way to mislead that a digest name did not have. A file called
`2026-08-18 drop the private export — author.claim.txt` whose contents vouch
for some other revision entirely forges nothing — the signature is over the
contents, and the contents are what counts — but a person reading the folder is
misled, and reading the folder is the entire point of the scheme. The note is
the answer, and `arrange` is the repair. A design that makes a directory worth
reading owes the reader a check that what they read is true.

### `arrange`

`historica-minisign arrange` re-files every claim under the name this scheme
chooses, renaming and never rewriting, exactly as `historica arrange` does for
revisions and for the same stated reason: only `arrange` renames, because a
writer names the file it is creating rather than renaming it afterwards. It is
the migration for a store written under 0001, the repair for a claim that
arrived misfiled, and the tidy-up after a hand-written claim.

`sign` does not run it. A command that vouches for a revision should not also
move other people's files.

## Rejected alternatives

**Keeping the digest name and printing a readable index.** A second file
listing what each hash contains is a second source of truth that goes stale,
and it answers the reading problem while leaving the hand-authoring problem
exactly where it was. The folder is the interface.

**Naming a claim from the claim's bytes alone, readably** — its `when`, its
role, and a truncated revision digest. This keeps 0046's union guarantee
unconditional, because the name never depends on anything outside the file. It
was rejected because the resulting name says when somebody signed and not what
they signed, and "what they signed" is the question a person opens the folder
to answer. The guarantee it preserves is preserved well enough by `arrange`;
see below.

**A summary line inside the claim.** It would make the readable name derivable
from the claim alone, and it is the wrong answer twice: 0001 rejected a message
field on the grounds that a claim says exactly one thing, and a signed summary
of a revision is a signed assertion that can disagree with the revision it
summarises. The name may be misleading and correctable. A signed line may not.

**Making a misfiled claim an error.** It would make every hand-written claim a
failure until its author guessed this scheme, which is the outcome this
decision exists to prevent.

## Consequences

- The union guarantee weakens in one stated way. Two copies that disagree about
  whether they hold a claim's revision will file that claim under two names.
  Both files hold identical bytes, both verify, `verify` counts them once, and
  `arrange` reduces them to one. Historica accepts the same weakening for
  revisions — 0019 has a writer take a collision suffix that `stems` would not
  have given it, and says of the result that "both spellings are unambiguous in
  the meantime". This is that, and no worse.
- `verify` now parses every revision document to compute canonical names, where
  before it parsed none. The bytes were already read at open; this is parsing,
  not I/O, and it is what `historica arrange` already pays.
- A store written under 0001 verifies unchanged, forever. A store written under
  this decision is not readable by a 0.1.0 `verify`, which reports its claims
  as `Foreign` and counts none of them. That is a behavioural change of the
  kind that must be recorded on the commit, and it is why this arrives before
  1.0 rather than after.
- `claim-0` does not change. Not one byte inside a claim moves; a `claim-0`
  written in 2026 under a digest name is the same document under its new name,
  and its signature is still valid, because the signature never covered the
  name.
- Historica's 0046 is amended, in the historica repository, in the commit that
  accompanies this one.
