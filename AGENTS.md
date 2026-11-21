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
- `cargo deny --all-features check`
- `cargo audit`

A byte parser, header decoder, or other function that accepts untrusted
bytes lands with a `cargo-fuzz` target in the same change. See `fuzz/README.md`.

## Security review

Astra (`openai/gpt-6.2-astra`) reviews a change that touches parsing,
cryptography, authorization, or the proxy. Ask whether a named invariant
holds at a named revision. Ask for the file and the fix if it does not.

Do not ask Astra for an exploit, a bypass, a payload, a proof of concept,
or reproduction steps. Do not paste a secret, a key, or a passphrase into
the request. If a review comes back as a refusal, narrow it to the
invariant and the function. Do not rephrase it as an attack.

The integration branch is `dev`, not `main`.

Product decisions and competitor research live in the atlas notebook
`projects/neo-air-vault/`. Do not copy that notebook into this repository.
