# neo-air-vault

neo-air-vault is a credential and secrets store for people, service accounts,
and agents. It is not usable yet. This repository is the Rust workspace for
that product. The crate in `crates/neo-air-vault` does not store or encrypt
secrets.

It uses Rust 1.100 and is licensed under MIT.

## Build

From this directory, with the pinned toolchain:

```sh
cargo test --workspace --all-features --locked
```

`cargo test` checks that the workspace builds. It does not test a vault,
because there is no vault.

## What this is not

- Not a password manager you can log in to.
- Not a FIPS-validated module.
- Not post-quantum safe. No cryptographic algorithm is implemented here.
- Not a client for Bitwarden, 1Password, KeePass, Vault, OpenBao, Azure Key
  Vault, Dashlane, Proton Pass, Infisical, or Vaultwarden.

The first implementation has not started. Do not point a workload at this
repository.
