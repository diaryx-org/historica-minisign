---
title: Signing a digest it was told about
description: `sign` resolves a target or falls back to the head; it should also read historica's `historica-wrote-1` statement from stdin and sign what a command just wrote
status: open
created: 2026-09-02
updated: 2026-09-02
part_of: "[Tasks](tasks.md)"
---

# Signing a digest it was told about

`sign` takes a target — `head`, a bookmark, a change ID or a digest — and
resolves it against the store (`src/cli/target.rs`), defaulting to the head.
That is the right shape for a person at a prompt, and the wrong one for the
thing this tool is for: signing what a `historica` command *just* wrote.

Historica's decision 0074 gives the missing half. A writing command run with
`--fields` prints a small statement of where to look:

```text
historica-wrote-1
revision <digest>
name <bookmark>
```

So the composition is a pipe, with no state, no config and no registry between
the two tools:

```sh
historica record --fields -m 'note' | historica-minisign sign --wrote -
```

This is the only automatic historica's decisions permit. 0053 and 0072 both
refuse dispatch from `historica` into tools beside it, so what makes signing
happen on every capture is the person's alias or wrapper script — and this task
is what makes that alias one line rather than a shell function that parses
sentences meant for eyes.

## The work

- **`sign --wrote <path>`**, with `-` for stdin, reading the
  `historica-wrote-1` statement and signing every `revision` line in it.
- **Wrote nothing signs nothing, and exits zero.** A header with no lines is
  0074's most useful case, because it is what lets a wrapper do nothing at all.
  A statement with a line kind this build does not know is discarded whole, per
  0074, which means a non-zero exit rather than signing part of it.
- **Use historica's parser, not a second implementation.** The grammar is
  historica's, and its decision 0053 says a tool beside it takes what it needs
  from the API. `src/cli/target.rs` explains why it does the opposite for target
  spelling — historica's own lives in its binary — and that reasoning does not
  apply here, because the parser is a task in historica and is being written to
  be public. This one is blocked on it.
- **`--wrote` and a target are mutually exclusive**, and the head fallback does
  not apply: the statement is the target.
- Claims are filed exactly as they are today, under decision 0003.

## Not in this

**Verify needs nothing.** The receive-side composition already works:

```sh
historica receive --fields ../other | historica-minisign verify --complete
```

A wrapper that sees any line runs `verify`, and the verdict is over the store as
it stands rather than over what arrived, so no `--wrote` is wanted on that side.
A claim arriving only ever moves a revision from unvouched to vouched, so there
is nothing this tool needs told about the reserved directories either.

**No gate before a receive.** Refusing unvouched history at the door is
historica's decision 0046, deferred to a need-first trait, and the one
in-process host has declined it: refusing at the door leaves a reader with
nothing to look at and no way to judge what they were asked to judge. It also
cannot be done from a command line, because trust never travels — before the
receive the claims are in the other store and the trust is here, and no tool
holds that split. Receive, then verify, then decide.

## Done when

- `historica record --fields -m x | historica-minisign sign --wrote -` files a
  claim over the revision that command wrote.
- An empty statement signs nothing and exits zero; an unknown line kind signs
  nothing and exits non-zero.
- The README's synopsis shows the pipe, since it is the shape this tool is meant
  to be used in.
