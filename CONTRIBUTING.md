# Contributing

Thanks for your interest in Basilisk. This is a personal engineering project; contributions and issues are
welcome but reviewed as time allows.

## Ground rules

- Keep changes focused and behavior-preserving unless the change is the point.
- Match the existing code style; run `cargo fmt --all` before committing.
- Keep comments minimal and meaningful: explain *why*, not *what*. No narration or restating of code.
- Add or update tests for behavioral changes. Behavioural output is checked against a plain-`luau` oracle.

## Before opening a PR

```sh
cargo fmt --all --check
cargo clippy --all-targets
cargo test
```

The `luau` CLI must be on your `PATH` for the behavioural tests to run.

## Scope

Basilisk is a Luau obfuscator and compiler project. Bug fixes, correctness improvements, new
transformation passes, documentation, and tests are all in scope. Please open an issue to discuss larger
design changes first.

## Security

See [SECURITY.md](SECURITY.md). Please do not file public issues for anything that looks like a real
vulnerability; use the private contact there instead.
