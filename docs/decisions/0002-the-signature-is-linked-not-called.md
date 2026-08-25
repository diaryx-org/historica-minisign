# 0002 — The signature is linked, not called

historica-git's decision 0002 reaches git as a program: no library is linked,
`git` must be on `PATH`, and the whole of the contact with git is a stream it
writes. The same question arrives here — minisign is a command, and there is a
Rust crate for it — and it gets the opposite answer. This decision is why, so
that the pair of them does not read as an inconsistency.

## The decision

**`historica-sign` links `minisign` for signing and `minisign-verify` for
verifying. Neither the `minisign` command nor any other program is required for
any operation.**

The signing half is behind a `sign` feature, on by default. `default-features =
false` leaves a library that can only verify, and its whole dependency is
`minisign-verify`, which has none of its own.

## Why this differs from historica-git

The git decision turned on git being *installed wherever the conversion is
wanted*: nobody converts a repository they do not have git for, so requiring
the program costs nothing and buys the enormous surface of git's own
correctness. Every premise of that inverts here.

- **Almost nobody has minisign installed.** It is an excellent small tool with
  a small audience. Requiring it means the first thing this tool says to most
  people is "install a C program first", and a trust layer that is not started
  is a trust layer that protects nothing.
- **The surface being bought is small and stable.** Ed25519 over a BLAKE2b
  prehash, in a file format of four lines. This is not git's twenty years of
  edge cases; it is an algorithm with test vectors.
- **The dependency would land on the wrong side.** Verification is the
  operation that has to work everywhere — in CI, on a machine that only reads,
  and eventually inside historica's own `receive` if 0046's deferred
  enforcement is ever built. A verifier that shells out to a program is a
  verifier that fails on the machines most likely to be running it.

## What linking is not allowed to cost

The interoperability, which is the point. `minisign` the crate is
rust-minisign, the reference implementation's own; the artifacts it writes are
minisign artifacts, and decision 0001 requires the tool to write exactly what
the command writes and to accept exactly what the command accepts. Tests pin
both directions against the real command wherever it is on `PATH`.

So the person who does have minisign installed loses nothing: they can sign a
claim this tool wrote with `minisign -Sm`, verify one this tool signed with
`minisign -Vm`, and never install this tool at all — which is the property
0046 asked for when it said checking a claim by hand is two commands and
neither is Historica.

## What it does cost, stated

A secret key, a password prompt, and a key generator now live inside this
crate rather than in a program somebody else maintains. That is real, and it is
why the `sign` feature exists: the code that touches a secret key is the code a
verifier never builds.

## Rejected alternatives

**Shell out for both.** The premises above, in full.

**Shell out to sign, link to verify.** Tempting — the secret key would never
pass through this crate's memory — but it makes signing the operation that
needs the rarer setup, when signing is the one people must do first for the
design to be worth anything. The password prompt it avoids is `rpassword`, one
small dependency, reached through the minisign crate itself.

**Vendor a copy of the signing code.** A third implementation of a format that
already has two, maintained by someone with no reason to.
