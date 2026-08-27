# 0001 — A claim is a file beside the history

Historica's decision 0046 asked who vouches for a revision, answered that the
trust layer is a separate tool, and fixed the boundary that tool works under:
what its files are, where they live, and the one promise the store makes about
them. It also declined to pick the tool's grammar — "the grammar belongs to the
tool's own specification". This is that specification, and it is the first
decision this repository has to make, because every other one is about files
whose shape is settled here.

What 0046 already settled, and what this decision may not reopen:

- Claims live in `history/claims/`, immutable and digest-named, and the
  signature sits beside the claim it signs.
- The trust policy is `history/trust/`, one key to a file, and it never crosses
  a store boundary.
- The signature is minisign, detached, over the claim's own bytes.
- `verify` reads and never writes, and reports in 0006's split: errors are
  faults, notes are observations. A store with no claims verifies vacuously.
- Historica gains no command, no dependency, and no grammar.

## The decision

### A claim document

```
claim-0
revision 33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a
role reviewer
key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
when 2026-08-24T09:12:04-06:00
```

UTF-8, Unix line endings, a final newline, and no body. Five lines, always
these five, always in this order:

- `claim-0` — the preamble, naming the one grammar this document is in. It is
  spelled with its number because a claim is not a Historica document and must
  never be mistaken for one; a reader that meets any other spelling refuses the
  file rather than guessing.
- `revision <digest>` — 64 lowercase hex characters. What is vouched for.
- `role <role>` — in what capacity. One to thirty-two characters from `a`–`z`
  and `-`, beginning and ending with a letter.
- `key <base64>` — the minisign public key, spelled exactly as `minisign.pub`
  spells it on its second line, which is what makes it copyable between the two
  by hand.
- `when <timestamp>` — `YYYY-MM-DDThh:mm:ss±hh:mm`, Historica's one spelling of
  a moment, borrowed rather than re-specified. No fractional seconds, no `Z`,
  no `-00:00`.

**A header this grammar does not name is refused, and so is a repeated one, a
missing one, and one out of order.** This is the opposite of Historica's
tolerance, deliberately. Historica hashes and ignores an `x-` header because a
document it does not fully understand still states what it states, and the
digest keeps everyone honest. A claim is read to answer *should I believe
this*, and a reader that ignores what it does not understand answers that
question wrongly the first time the grammar grows: an `expires` line, or a
`scope`, or an `only-for`, would narrow what the signature covers, and a reader
skipping the line it had never seen would accept a claim its author had already
limited. Failing closed costs an old reader the claims it cannot judge, which
is the right thing for it to say about them. `claim-1` is how this grammar
grows, and an old reader refusing a `claim-1` is that rule working.

### What the files are called

A claim is `<digest>.claim.txt`, where the digest is the SHA-256 of the claim's
own bytes. Its signature is `<digest>.claim.txt.minisig`. Neither is ever
rewritten, and a second claim over the same revision by the same key at the
same moment is the same bytes and therefore the same file — which is what makes
two copies of a store union without a conflict, and what makes signing twice
cost nothing.

The `.minisig` suffix is minisign's own, so that

```console
$ minisign -Vm 4d8f….claim.txt -P RWTd8LRC…
```

finds the signature without being told where it is. That is the whole reason
for the name: checking a claim by hand must be the command a person already
knows.

### The trust policy

`history/trust/`, one key to a file, on 0045's container — the filename is a
label for whoever opens the folder, and the content is the fact:

```
trust-0
key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
who Adam Harris <adam@example.com>
```

A line beginning `#` states nothing, and a file of nothing but comments states
nothing at all — which is what the tool writes when it first creates the
directory, so the grammar is explained where the files are rather than only
here. `who` is free text to the end of the line: it is a label for a person,
not an identity the tool checks, and pretending otherwise would invite somebody
to match on it.

Entries are written with `create_new`, so two additions on one machine cannot
lose one. Removing an entry is deleting its file. Nothing here ever travels;
0046 argues that at length and this decision does not revisit it.

### What `verify` says

Errors — the store holds something that is wrong, and no reading of it is
charitable:

- A claim whose bytes do not parse.
- A claim whose filename does not state the digest of its own bytes. Historica
  says of exactly this case that "the name is a claim and it is false".
- A claim whose signature does not verify under the key the claim itself names.
- A claim with no signature beside it.
- A signature with no claim beside it.

Notes — the store is intact and something is worth saying about it:

- A claim by a key `trust/` does not hold. The claim is real; this copy has no
  opinion about who holds the pen.
- A claim naming a revision this store does not have. Claims travel by file
  sync and history travels by `receive`, so one arriving before the other is
  ordinary rather than wrong.
- A revision no trusted key vouches for.

**An unsigned claim is an error, and this is the one place where the split
above was not obvious.** A claim on its own asserts something and backs it with
nothing, and a reader who reads the claim without noticing the absent signature
believes it — which is not a hypothetical failure but the cheapest possible
attack on this design, costing an attacker one text file. Making it an error is
what stops the absence being quiet.

`verify --complete` promotes "a revision no trusted key vouches for" to an
error, which is the form the check takes in somebody's CI. It is the same word
`historica check --complete` uses, for the same kind of upgrade.

Coverage follows 0046: a claim over a revision covers every revision that
revision descends from, because a digest pins its bytes, which pin its parents'
digests. A store where the newest revision is claimed is a store where
everything is claimed, and that is a feature rather than a shortcut.

### The key

The default secret key is minisign's own — `~/.minisign/minisign.key` — and
`--key` names another. No new key format is invented, no key is stored in the
store, and a key generated by `minisign -G` years ago works here with nothing
done to it.

`historica-minisign key new` exists anyway, because the alternative is telling
somebody their first signature requires installing a C program, and a trust
layer nobody starts using protects nothing. What it writes is a minisign key
pair, in minisign's format, at minisign's default location — a file the
`minisign` command will pick up unchanged if that is ever installed.

### Byte-compatibility, both directions, pinned

A claim signed by this tool verifies with `minisign -Vm`, and a claim signed by
`minisign -Sm` verifies here. The tool therefore imposes nothing on the
signature's comments: the trusted comment is whatever the signer wrote, and
this tool writes what the minisign command writes, so the artifacts are
indistinguishable. Nothing informative goes in the untrusted comment — it is
untrusted, and a reader who learns to read facts there has learned the wrong
habit. Everything a claim says is in the claim, where the signature covers it.

Tests pin both directions against the real `minisign` command where it is on
`PATH`, and skip when it is not, so a machine without it can still run the
suite green.

## Rejected alternatives

**An open header space, with unknown headers ignored.** Argued above: it makes
every future narrowing of a claim invisible to an old reader.

**A closed vocabulary of roles.** `author`, `reviewer`, `release` are the
obvious three and there is no fourth this tool has standing to refuse. A role
is what a person says they were doing; the tool's job is to make it legible and
signed, not to approve it.

**A message or comment field in the claim.** The signature covers the whole
document, so a body would be signed and safe — but it would be the only place
in the design where a claim says something a reader has to interpret, and a
claim's value is that it says exactly one thing. If a claim ever needs prose,
`claim-1` can carry it, and old readers refusing it is the correct outcome.

**Putting facts in the trusted comment.** It is signed, so it would be sound,
but it would split the document in two — half in the file, half in the
signature — and `minisign -Vm` prints only the second half. One document,
one place.

**A key in the store.** `trust/` holds public keys and never travels; secret
keys are the operating system's problem and stay there.

## Deferred

**Head statements.** 0046's second document kind — a key, a counter, and the
heads its history had at that moment — is specified there and not built here.
It answers rollback, it needs a counter store and a monotonicity rule, and it
is worth its own decision rather than a paragraph in this one.

**Trusting a key for some roles only.** "This key may vouch as `reviewer` but
not as `release`" is a real policy and a small addition to `trust-0` — and one
nobody has asked for yet. It waits for the need, on 0045's discipline.

**Naming a claim's subject by anything but a digest.** A claim over a change ID
would follow amendment, which sounds convenient and is exactly the property a
signature must not have.
