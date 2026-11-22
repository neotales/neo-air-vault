# Security

This repository does not store or encrypt secrets yet. Do not deploy it.
Do not treat a clean scan of the placeholder crate, or a healthy
`navault-server` process, as a review of a vault. `/health` is not a
secret API.

## Gates

From the repository root:

```sh
cargo deny --all-features check
cargo audit
```

`cargo deny` is 0.20.2. `cargo audit` is 0.22.2. A missing tool is a
failure, not a skip. Advisories, yanked crates, and unknown git sources
fail the build.

Fuzzing starts when a byte parser exists. The rule is in `fuzz/README.md`.
The GitHub workflow builds targets when `fuzz/fuzz_targets` contains Rust
sources. An empty directory does not mean the parser was fuzzed.

## Reviews

Security review of a change that touches parsing, cryptography,
authorization, or the proxy is done by Astra (`openai/gpt-6.2-astra`).
The request names the revision and the invariant. It asks whether the
invariant holds, and for the fix if it does not.

The request does not ask for an exploit, a bypass, a payload, or a
reproduction. A finding is a file, the broken invariant, and the change
that restores it.
