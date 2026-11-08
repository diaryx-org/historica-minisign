---
title: A link to write renders as brackets
description: '`write_statement`''s doc links to `[`write`]`, which rustdoc cannot tell from the `write!` macro, so the page shows the brackets instead of a link; CI runs no `cargo doc`, so nothing reports it'
status: open
created: 2026-11-08
updated: 2026-11-08
part_of: "[Tasks](tasks.md)"
---

# A link to write renders as brackets

`sign::write_statement`'s doc comment (`src/sign.rs`, line 186) ends
"for the reason [`write`] gives", meaning `sign::write`. The prelude also
holds the `write!` macro, so rustdoc cannot tell which `write` the link
means, links neither, and the rendered page reads, brackets and all:

> `stem` is `crate::naming::statement_stem`'s answer, for the reason
> [`write`] gives.

The reader is sent to the one function whose doc carries the reasoning and
gets no link to follow.

## Repro

At 0cb2a88:

```console
$ RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features
error: `write` is both a function and a macro
   --> src/sign.rs:186:7
    |
186 | /// [`write`] gives.
    |       ^^^^^ ambiguous link
```

Without `-D warnings` it is the crate's one rustdoc warning, and
`target/doc/historica_minisign/sign/fn.write_statement.html` holds
`[<code>write</code>] gives` as plain text.

## Why nothing caught it

`.config/ship.figl` runs fmt, clippy, test, verify-only and msrv. None
builds the docs, so a broken or ambiguous intra-doc link compiles, passes
CI, and only shows on the rendered page. fs-transaction's `ship.figl` has a
`doc` job (`RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features
--no-deps`) for this reason.

## Done when

The link resolves to `sign::write` (``[`write()`]`` or ``[`write`](fn@write)``),
`RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features` passes, and
whether `ship.figl` gains a `doc` job like fs-transaction's is decided.
