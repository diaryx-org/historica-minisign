# 0005 — A key states its heads

Historica's decision 0046 named two document kinds and this repository has
built one. The second is the half of 0046's argument that a claim cannot
make:

> A signature never stops being valid, so a store can present a subset of a
> history — every document intact, every claim verifying — and the subset lies
> by omission.

and its answer:

> **A head statement is a claim.** A second document kind, same signing, same
> directory: this key, a counter, and the heads its history had at that
> moment. A verifier keeps the highest counter it has seen for each key and
> refuses a statement below it.

Decision 0001 deferred it because "it needs a counter store and a
monotonicity rule, and it is worth its own decision rather than a paragraph".
The need has arrived: pedantic, the knowledge core in diaryx, gives every
revision in a shared workspace a signature and needs a store to be unable to
hide the revision that took someone's authority away. Its proposal says so in
one line — "head statements are what stop a store from hiding the removal
indefinitely" — and puts them here.

## The decision

### A `heads-0` document

```
heads-0
key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
counter 7
when 2026-10-07T09:12:04-06:00
head 33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a
head 9a1c0e7d55b2f3e4a6c8d0f1b3a5c7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1
```

- **`key`, `counter`, `when`, in that order, then one `head` line per head.**
  Everything 0001 says about encoding, line endings and the final newline
  holds, and so does its load-bearing rule: a line the grammar does not name
  is refused, never skipped. A later grammar that narrows a statement is
  `heads-1`.
- **The heads are ascending by digest, each stated once, and there is at
  least one.** It is the one place a header repeats, so the order inside it is
  fixed, which gives one statement one spelling and therefore one digest and
  one file however many copies write it. A store with no revisions has
  nothing to state.
- **The counter is a decimal number from 1, with no sign and no leading
  zero.** A count rather than a time, because a clock can be set back and a
  reader cannot tell; `when` is there for a person and nothing compares it.
- **A statement names the store's heads by parent edges**, every one of them,
  including an amended revision its successor has not yet let `prune` take.
  "Everything I had" is the claim, and a verifier is told below what to make
  of a head that has since been pruned.

The signature is minisign, detached, beside the statement, exactly as a
claim's is. `minisign -Vm` checks one by hand, and the heads it names are
`ls history/revisions` away.

### Filed under `claims/heads/`, by key

```
claims/heads/3f9a0c1e/7.heads.txt
claims/heads/3f9a0c1e/7.heads.txt.minisig
```

`claims/` because historica's decision 0053 classes it `travels-and-unions`,
and a statement that did not travel would protect nobody. A directory per key,
named as decision 0003 names a key, and the counter as the file's name, so a
person opening the folder reads one key's statements in the order it made
them. A second statement by one key at one counter takes its own digest after
the counter, which is the claim naming rule's last tier for the same reason:
the name is derived from the document and never from what else is in the
directory.

### What a verifier asks

For every key this copy believes, `verify` takes the highest-counted statement
whose signature holds and asks:

- **Does this store hold every head it names?** A head the store lacks, which
  no revision the store holds supersedes, is **withheld**: the store is a
  subset of a history that key has already shown somebody. An error. A
  superseded head is excused because `prune` takes exactly those, and a
  store that pruned after the statement holds the revision that replaced it.
- **Did the key state two things at one count?** Two different statements at
  one counter, both signed, is an **equivocation**: an error, because one key
  cannot honestly have done it.
- **Is it at least as high as what this copy has witnessed?** If this copy has
  seen the key at a higher count, or at the same count saying something else,
  the store has been **rolled back**, or the key has equivocated across
  stores. An error.

A key nobody here believes is not judged. Anyone can write into a store that
anyone can write claims into, and a store must not be one that anyone can fail
by doing so: an unbelieved statement is the `Untrusted` note a claim already
gets, and nothing more.

### What this copy has witnessed lives under `trust/seen/`, and is rewritten

```
seen-0
key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
counter 7
statement 4b1d…
```

One file per key, named by the digest of the key's text — never a prefix of
it, because two keys sharing a prefix would share a file and the second to be
witnessed would erase the first's mark without a word.

`trust/` because 0053 classes it `local-only`, and the record is this copy's
opinion of what it has been shown. A store that could send a reader a lower
high-water mark could undo the only thing this record is for, which is 0046's
argument for why trust never travels, applied to the one other thing that
must not.

It is the only file this tool rewrites, and it only goes up. It is raised by
`historica-minisign witness`, never by `verify`, which reads and never writes
(0046). A key `verify` found withheld, equivocating or rolled back is not
witnessed, because recording a store in that state would record the fault as
the new normal.

### Stating

`historica-minisign state` signs every head the store has, at one more than
the highest count it can find for that key — in the store, or in this copy's
record, whichever is higher. The second matters: a store that lost a key's
latest statement must not lead the key to state a lower count, which every
copy that saw the higher one would refuse.

## What this does not do

**Freshness.** A statement detects regression from anything a verifier has
witnessed. It cannot detect a newer statement that was never shown. 0046
declines statements that expire, because a store moved by `cp -r` and dormant
for a year should not have a trust layer that rots on a calendar, and this
declines them for the same reason.

**`arrange` for statements.** Their names are presentation, as a claim's are,
and nothing reads them. A misfiled statement is still read and counted.
`verify` does not note one yet; that waits for a store that has one.

**Saying who must state.** Whether a store is incomplete without a statement
from some key is a policy over this mechanism, and the tool that needs one —
pedantic, for a shared workspace — states it there.
