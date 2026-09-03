---
title: Tasks
description: Deferred work in historica-minisign — one file each, every one with a done state
created: 2026-09-02
updated: 2026-09-02
contents:
  - "[Signing a digest it was told about](signing-a-digest-it-was-told-about.md)"
---

# Tasks

Work this project has committed to and has not done yet, one document each. A
bug is a task with a repro; anything else is a task with a done state written
down, so that finishing it is a fact rather than an opinion.

`contents` above lists what is **open**. Closing a task is an edit, not a
delete: its `status` becomes `done` or `dropped`, it names the commit or release
that resolved it, and it leaves the list above while the file stays where it is,
findable by grep.

What does not belong here: what shipped, which is the README and the
[decisions](../decisions); and a commitment to consumers, which is the
[changelog](../CHANGELOG.md)'s unreleased region or a `Behavioural-change:`
trailer.

`status` takes `open`, `in-progress`, `done`, or `dropped`, and nothing else,
so that a tool can read it across every repository in the org.
