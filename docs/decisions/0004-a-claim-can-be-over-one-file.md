# 0004 — A claim can be over one file

Decision 0001 wrote one kind of claim: a key vouches for a revision, and by its
digest for everything that revision descends from. It also said how the grammar
would grow: "`claim-1` is how this grammar grows, and an old reader refusing a
`claim-1` is that rule working". This is the first time it grows.

The need comes from pedantic, the knowledge core over prov and historica that
diaryx's proposal *A knowledge core over prov and historica* argues for. Its
§3 asks for "a claim over one file at a revision", one that "names the
file's content digest, and stands while that is the content digest now", and
its *What moves where* gives that to this repository. A reviewer who read one
document has two bad choices under `claim-0`:

- **Vouch for the whole revision.** That says they stand behind every other
  file in it, and every revision behind it. They did not read those, so the
  claim overstates what they did.
- **Vouch for nothing.** That leaves the review unsigned.

A whole-revision claim also cannot outlive its revision in any useful sense. A
writer who appends a confirmation to the document an hour later makes a new
revision, and the reviewer's claim covers the old one. What the reviewer read
did not change, and nothing in `claim-0` can say so.

## The decision

### A `claim-1` document

```
claim-1
revision 33f863f19e9b19f47ae42e41b4c25f03acc3c14acca2da65ea6bb141016b487a
file kmnpqrstvwxzkmnpqrstvwxz
content sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
role reviewer
key RWTd8LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
when 2026-10-03T09:12:04-06:00
```

Seven lines, always these seven, in this order: what is vouched for first, then
in what capacity, by whom, and when. Everything 0001 says about encoding,
line endings and the final newline holds unchanged, and so does every header
`claim-0` shares with it.

- `file <file ID>`: Historica's file ID, twenty-four characters from `k` to
  `z`. The ID, not the path. Historica's decision 0008 makes a path a fact
  *about* a file. A rename keeps the ID, so a claim over a file follows it
  through a move. A path would not, and would name a different file once
  something else took that path.
- `content <algorithm>:<value>`: the file's **content digest**, as the
  claimant's tool computed it. The algorithm is one to sixteen characters of
  `a`–`z`, `0`–`9` and `-`, beginning with a letter. The value is one to 128
  characters of ASCII letters, digits, `-` and `_`. That holds hexadecimal and
  unpadded URL-safe base64, and it is never more than one token on one line.

**This crate never computes a content digest, and never interprets one beyond
its spelling.** Which bytes of a file are *content* is the claimant's tool's
knowledge. For pedantic it is prov's digest of a document without its
`confirmed:` list. Excluding that list is what lets a writer confirm a document
afterwards without unseating a reviewer's claim on it. A digest of the raw bytes
would be unseated by exactly that bookkeeping edit. Two digests are equal when
they are the same characters. Nothing is lowercased or normalised, because the
tool that compares them is not this one. The algorithm is required so that such
a tool can tell a digest it cannot compare from one that differs.

### The preamble picks the grammar, and each grammar has one shape

`claim-0` is the whole-revision grammar of five lines. `claim-1` is the
one-file grammar of seven lines, and its `file` and `content` lines are not
optional. A whole-revision claim is always written as `claim-0`, never as a
`claim-1` with two lines left out.

That gives one claim one spelling, and two properties depend on it. Decision
0001 makes a claim's identity the digest of its bytes, so that the same claim
written twice is one file and two copies of a store union without conflict.
Two spellings of one whole-revision claim would be two files and two
identities for one statement. And every store written before this decision
stays exactly as it was. A whole-revision claim signed today is byte for byte
what it would have been in August, and a reader built before this decision
reads it.

Strictness is unchanged. An unknown header, a repeated one, a missing one, one
out of order, or a line past the last header is refused, in either grammar. A
`claim-0` reader meets `file` on line 3 where it expects `role`, and refuses the
document. 0001 asked for exactly that: the old reader cannot see that the claim
was narrowed, so it does not count it as covering anything. One change in how a
refusal is *reported*: the check for lines past the last header now runs after
the headers are read rather than before. A document with a narrowing line
inserted is therefore named by that line (`Unknown`, at line 3) rather than
counted as one line too many (`Trailing`). Both are refusals.

### What `verify` says about a claim over one file

A one-file claim holds when three things are true:

- its signature verifies under the key it names
- this copy holds the revision it names
- that revision's tree holds the file it names

`Held::file` says what the tree said. `Found` carries the file's path at that
revision. `Missing`, `Unknown`, and `Whole` cover the rest. `Held::counts()` is
true for a one-file claim only when it is `Found`, as well as signed by a key
this copy believes. A whole-revision claim's `counts()` is unchanged.

Two findings are new or newly reached:

- **A one-file claim over a file its revision does not hold is an error**,
  `NoSuchFile`. The revision is here, so its tree is everything there is to
  know, and nothing is still arriving. The claim vouches for something that was
  never at that revision. The split between errors and notes in 0001 puts that
  with a refused signature, not with an absent revision.
- **A one-file claim over a revision this copy does not hold** is the same
  `Absent` note a `claim-0` gets, because claims and history travel separately.
  Its file is `Unknown`, and it does not count until the revision arrives. A
  whole-revision claim over an absent revision has nothing to vouch for here
  either, so the two behave alike in what they cover.

A tree that will not replay is `historica check`'s finding, not this tool's.
The file is then `Unknown` and the claim does not count. When a claim cannot be
checked, it fails closed.

### A claim over one file vouches for no revision

`Report::vouched`, `vouches_for` and `complete` are whole-revision questions. A
one-file claim never enters `vouched`, never covers ancestry, and never makes a
head vouched for. It reaches `complete` only the way any claim does, by being
an error and so making the store not `ok`:

- **Not the revision.** The claimant read one file and said so. Counting that
  as vouching for the revision is the overstatement this decision exists to
  remove.
- **Not the ancestry.** A whole-revision claim covers ancestry because the
  claimant signed a digest that pins the parents' digests. A one-file claim
  names a revision only to say which state of the file was read. The claimant
  looked at none of the history behind it.
- **Not `complete`.** `verify --complete` is somebody's CI refusing history
  nobody stands behind. If a claim over one file in a thousand-file revision
  made that pass, the check would be easier to satisfy without checking
  anything more.

### Whether a claim stands is the caller's question

A one-file claim *stands* while the content digest it names is the file's
content digest now. Only the claimant's kind of tool can compute that, so the
report hands over the material and leaves the judgement to the caller:

- `Report::vouched_files()`: every one-file claim that counts, each with its
  file and content digest through `Claim::file()`
- `Report::vouches_for_file(file, content)`: whether any of them names this
  file with this content. It is the comparison a reader's tool makes, given the
  content digest it computed for the file now. A claim made at any revision
  answers it, which is the point: a later revision that left the content alone
  does not unseat it.

`verify::find_file(store, revision, file)` is the tree check on its own. A
writer uses it to avoid writing a claim that `verify` would call an error.

### Where a claim over one file is filed

Decision 0003's scheme, with the file's ID, abbreviated to eight characters,
after the role:

```text
history/claims/2026-08/2026-08-18 drop the private export — reviewer.claim.txt
history/claims/2026-08/2026-08-18 drop the private export — reviewer mpqzkxtn.claim.txt
```

Without it, a reviewer's claims over several files of one revision would all
share one base name and fall straight to the last tier, a claim digest. The ID
is spelled in `k`–`z`, so it is always a filename. Where the revision is
absent, the fallback name gains the same suffix. Collision tiers are unchanged.

### The command line

`sign --file <path or file ID> --content <digest>` writes a `claim-1`. The
path is resolved in the target revision's tree, and a file ID is accepted
where no file sits at that path. Each flag requires the other. A file the
revision does not hold is refused before anything is written. `verify` lists a
one-file claim by its path, and says how many count, apart from the revisions
vouched for.

## Rejected alternatives

**An optional `file` line in `claim-0`, or optional file lines in `claim-1`.**
Decision 0001 refuses the first outright, and an old reader would skip the
narrowing it had never seen. The second gives a whole-revision claim two
spellings (above).

**The path instead of the file ID.** It is more readable, and it is the wrong
identity. A rename would make the claim name a file that is no longer there,
and a new file at the old path would inherit a claim nobody made about it.
`verify` reports the path at the claim's revision, which is where readability
belongs.

**Computing the digest here, from the file's bytes at the revision.** This
would make the claim checkable without the claimant's tool, but it is the wrong
digest for the case that motivates the decision. A writer's confirmation is an
edit to the file. A digest over all of its bytes changes when the writer
confirms the document, so every confirmation would unseat every reviewer's
claim. Which bytes are bookkeeping is the tool's knowledge, not this
repository's or historica's.

**Historica's payload digest.** A file of bytes has one (`Entry::payload`). A
file of lines, which is every Markdown document, does not. It would have the
same bookkeeping problem besides.

**Letting a one-file claim count towards `complete`, per file.** "Every file
at every head is vouched for, one way or another" is a policy someone might
want. It needs the current content digest of every file, which this crate
cannot compute, so it belongs to the tool that can.

## Consequences

- A store holding a `claim-1` read by a `verify` from before this decision
  reports it as `Malformed`, an error. Read by this one, the claim is read,
  checked and listed. That is a behavioural change and is recorded on the
  commit.
- `Claim` gains a `scope` field and `Held` gains a `file` field. Code that
  reads them is unaffected. Code that builds either with a struct literal must
  add the field.
- On a store that holds only `claim-0`, every answer `verify` gives is
  unchanged. A one-file claim adds nothing to `vouched` or `vouches_for`. It
  can change `ok`, and so `complete`, only by being an error itself.
- `Finding` gains `NoSuchFile`. It was already `#[non_exhaustive]`.
- `Scope` is deliberately *not* `#[non_exhaustive]`. A third scope would be a
  narrowing a caller has never judged, and a `match` that stops compiling tells
  that caller so. It is 0001's refusal, applied at compile time.

## Deferred

**`verify` asking about one file from the command line.** `verify <target>`
asks about a revision. Asking whether a file is vouched for needs its content
digest now, which the command cannot compute. The library has the question
(`vouches_for_file`), and a command can follow when a tool needs it.

**Head statements, and trust for some roles only**, deferred by 0001, stay
deferred.
