# Fuzz targets

`cargo-fuzz` targets live in `fuzz/fuzz_targets/`. `cookie_origin` exercises
the cookie and origin handling.

A change that adds a decoder, a header parser, or any function that accepts
a byte slice from outside the process must add a fuzz target in the same
change. The target calls that function and checks the invariant. It does
not embed a sample secret, a key, or a passphrase.

Build and run, on nightly, from the repository root:

```sh
cargo install cargo-fuzz --locked
cargo fuzz build
cargo fuzz run <target> -- -max_total_time=60
```

A one-minute run is the local check. It is not a proof. A crash is a
failure. Do not silence it with a corpus exception.
