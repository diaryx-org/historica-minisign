# Changelog

What has changed in historica-sign, release by release, for someone deciding
whether to move to a newer one.

Two halves, written two different ways.

The bulleted groups below — **Added**, **Fixed**, **Changed**, and a
**Behavioural changes** section under them — are **generated** from the commit
log by `cargo xtask changelog --write`, which reads `.config/cliff.toml`.
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

### Added

- the repository, its CI, and the claim a signature covers ([`4ba95fb`](https://github.com/diaryx-org/historica-sign/commit/4ba95fb65e50746916debe46796d82573da2135f))
- **trust** — one key to a file, and never from another store ([`3dfb980`](https://github.com/diaryx-org/historica-sign/commit/3dfb980fba9950b990bfc93701028076b6202d32))
- **verify** — what a store's claims amount to ([`67bb241`](https://github.com/diaryx-org/historica-sign/commit/67bb241416fc35e9d58f71cbf3e4a7565e5d2711))
- **sign** — a claim, written and signed ([`d0fc97c`](https://github.com/diaryx-org/historica-sign/commit/d0fc97cc32ca3d24913f1661ef273a410152bde4))
- **cli** — sign, verify, trust, and key ([`82ab514`](https://github.com/diaryx-org/historica-sign/commit/82ab514373c3db17d1093b5b7dad8d8cce358fc0))

<!-- git-cliff:end -->
