# Changelog

What has changed in historica-sign, release by release, for someone deciding
whether to move to a newer one.

Two halves, written two different ways.

The bulleted groups below — **Added**, **Fixed**, **Changed**, and a
**Behavioural changes** section under them — are **generated** from the commit
log by `release changelog --write`, which reads the shared `cliff.toml` in
diaryx-org/devtools — the same file, and the same style, in every repository
here.
Anything inside a `git-cliff:begin` / `git-cliff:end` pair is rewritten on every
run, so an edit made there is an edit thrown away.

Everything else is handwritten and stays: this prose, and any intro a release
needs under its own heading, below the end marker where regeneration cannot
reach it.

**Behavioural changes** are collected from `Behavioural-change:` trailers on the
commits themselves, not from their subjects — because "would a reader who
upgrades without editing a line of their own code observe a difference" is a
judgment about the change that no subject can carry. Write one trailer per
observable difference, as prose someone can act on.

One kind of change here deserves a trailer that would not obviously need one
elsewhere: **anything that changes what `verify` accepts or refuses**. A claim
that used to be a note and is now an error, or the reverse, changes what
somebody's CI does without a line of their code moving.

historica-sign has not been released, and cannot be until historica is:
decision 0002 explains why the dependency is spelled with both a version and a
path.

## Unreleased

<!-- git-cliff:begin — generated; edits here are overwritten -->

### Breaking

- **naming** — file a claim where it can be read ([`3bec795`](https://github.com/diaryx-org/historica-minisign/commit/3bec79524fc8ef0fc13d92b967602e459aee9888))

### Added

- the repository, its CI, and the claim a signature covers ([`4ba95fb`](https://github.com/diaryx-org/historica-minisign/commit/4ba95fb65e50746916debe46796d82573da2135f))
- **trust** — one key to a file, and never from another store ([`3dfb980`](https://github.com/diaryx-org/historica-minisign/commit/3dfb980fba9950b990bfc93701028076b6202d32))
- **verify** — what a store's claims amount to ([`67bb241`](https://github.com/diaryx-org/historica-minisign/commit/67bb241416fc35e9d58f71cbf3e4a7565e5d2711))
- **sign** — a claim, written and signed ([`d0fc97c`](https://github.com/diaryx-org/historica-minisign/commit/d0fc97cc32ca3d24913f1661ef273a410152bde4))
- **cli** — sign, verify, trust, and key ([`82ab514`](https://github.com/diaryx-org/historica-minisign/commit/82ab514373c3db17d1093b5b7dad8d8cce358fc0))
- **trust** — a trust entry is named for whose key it is ([`b6e519e`](https://github.com/diaryx-org/historica-minisign/commit/b6e519e1938bd0872d9f89ceaa9ee98ab479373c))

### Fixed

- **verify** — ask the store whether it holds a digest, not for the document ([`da7b972`](https://github.com/diaryx-org/historica-minisign/commit/da7b9728c5621b616986ea20d4f43a9e268573bf))
- **naming** — a key prefix is a digest, not the key's own text ([`e282a2f`](https://github.com/diaryx-org/historica-minisign/commit/e282a2f1a41ac2551de7bbba03694fd3c19ab796))

### Changed

- **xtask** — cut releases with the shared tooling, not a sixth copy ([`01f6991`](https://github.com/diaryx-org/historica-minisign/commit/01f69912a0b69a16a0f149e4e2f7a1e1896535ca))
- **release** — read the shared cliff config, not a local copy ([`398802d`](https://github.com/diaryx-org/historica-minisign/commit/398802db717bd3ddf8b4d8bb9fb453992c40c892))

### Behavioural changes

- `sign` writes claims under readable names in a month
 directory — `claims/2026-08/2026-08-18 drop the private export —
 author.claim.txt` — rather than `claims/<digest>.claim.txt`. Stores written
 before this verify unchanged and every claim in them still counts, but a
 store written after it is not readable by 0.1.0, whose `verify` reports its
 claims as `Foreign` and counts none of them. `verify` gains two notes,
 `Misfiled` and `Duplicate`, and `NameIsFalse` now fires only for a name that
 is actually a digest. `sign::write` takes the stem to file under as a new
 fourth argument; `layout::claim_file` and `layout::signature_file` take a
 stem rather than a digest. `claim-0` is unchanged, and a signature made
 before this is still valid, because no signature ever covered a filename.

- `trust add` names a new entry for the person it speaks
 for — `history/trust/Adam Harris.txt` — rather than for twelve characters of
 the key's digest. Nothing reads a label in either case, so entries already on
 disk are read exactly as before under whatever they are called; what changes
 is the name a person sees in the folder, and the label `trust list` prints
 and `trust remove` takes. Adding a second key for one `who` now succeeds
 under a suffixed name rather than failing as taken, unless the label was
 given with `--label`. `trust::default_label` takes the `who` it is naming as
 a second argument.

- `cargo xtask version`, `bump`, `changelog`, `release`, and
  `release-notes` no longer exist. Each now exits non-zero naming its
  replacement — `release <command>`, from diaryx-org/devtools, which must be on
  PATH. `cargo xtask ci` and the individual CI jobs are unchanged.

- releasing this repository needs diaryx-org/devtools on PATH
  for its git-cliff config as well as for `release` itself. Nothing in the tree
  configures git-cliff any more.

<!-- git-cliff:end -->
