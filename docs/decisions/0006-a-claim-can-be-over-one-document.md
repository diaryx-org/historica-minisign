# 0006 — A claim can be over one document

Decision 0001 wrote a claim over a revision, and 0004 narrowed it to one file
at a revision. Both name a revision, because until now everything worth
vouching for reached a store inside one.

A forgetting does not. Historica's decision 0014 makes a forgetting document a
stand-in for an operation document whose bytes were destroyed. It carries a
`forgets` header and no message, and no revision names it: it travels because
it was written, and a store that receives it destroys what it stands in for.
That is the one act in a store that cannot be undone, and it is the one act
nobody can sign. No revision exists for an `author` claim to name.

The need comes from pedantic, diaryx's knowledge core. Its step 4.5 holds a
forgetting nobody with authority over the document made, before any bytes are
destroyed. Holding it means knowing who made it, so the forgetting has to be
signed, and every copy has to be able to check the signature the same way.

## The decision

### A `claim-2` document

```
claim-2
document 6397b3a4b3b8abd444da81f2f731dd67c4f5bcea5dc03c4e8141783d1f1b4c53
role author
key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
when 2026-10-07T09:12:04-06:00
```

Five lines, always these five, in this order. `document` is the digest of one
document the store holds that is not a revision: an operation document, a
resolution, or a forgetting. The rest is `claim-0`'s.

The header is `document` and not `revision`. A `claim-0` reader meets
`claim-2` on line 1 and refuses it, as 0001 asks, and a reader of this
grammar never mistakes a document's digest for a revision's. A `claim-2` with
`revision` on line 2 is refused. In code the digest stays in
`Claim::revision`, with `Scope::Document` saying what it names: every claim is
over a digest, and the scope is what says which kind.

The role means what it means elsewhere. `author` over a forgetting is *this
forgetting is mine*, which is the question a copy asks before destroying
anything.

### What `verify` says about it

A claim over one document is present when the store holds that document, and
`Absent` otherwise, the same note a claim over an absent revision gets. It
names no file, so `Held::file` is `Whole`, and it counts when its signature
verifies under a key this copy believes.

It vouches for no revision. It never enters `Report::vouched`, covers no
ancestry, and makes nothing `complete`. A document's digest pins its bytes and
nothing else: a forgetting does not even pin the revision whose operation it
stands in for, since several revisions may name one operation document.

### Where it is filed

Decision 0003's naming already has a tier for a claim whose revision this copy
does not hold: the month, the date, the role and the digest. A document is
never a revision, so a `claim-2` always takes that tier:

```text
claims/2026-10/2026-10-07 author 6397b3a4b3b8.claim.txt
```

Nothing new is decided. The digest in the name is the document's.

## Rejected alternatives

**A `claim-0` over the forgetting's digest.** It would write today and verify
today, and every `verify` would report it as vouching for a revision the store
does not hold. That report would be true of the words and false of the claim.

**A revision that records the forgetting.** Historica's forget writes no
revision, by design (0014: a forgetting carries no message, because the
reason is usually the thing forgotten). A revision recorded only to be signed
would carry an author, a time and a parent for something that changes no
file, and would sit in every log as an empty change.

**A signature header inside the forgetting.** 0046 refused that for revisions
on the self-reference argument, and it applies unchanged: the digest a
signature covers cannot include the signature.
