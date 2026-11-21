# Repository constraints

All code lives in `crates/`. The workspace uses Rust 1.100, edition 2024, and
the MIT license. `publish` stays false until a release is an explicit decision.

This crate does not store secrets. Do not add a cipher, a database, or an HTTP
server in a drive-by change. A secret value must not be a bare `String` once
secret types exist. `unsafe` is forbidden.

From the repository root, using the pinned toolchain:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked`

The integration branch is `dev`, not `main`.

Product decisions and competitor research live in the atlas notebook
`projects/neo-air-vault/`. Do not copy that notebook into this repository.
