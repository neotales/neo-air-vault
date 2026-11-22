# neo-air-vault

neo-air-vault is a credential and secrets store for people, service accounts,
and agents. It is not usable yet. This repository is the Rust workspace for
that product. `server/` does not store or encrypt secrets.

It uses Rust 1.100 and is licensed under MIT.

The server binary is `navault-server`. The CLI binary will be `navault`.
The human client is `web/`. Both are a shell. Neither stores a secret.
`/health` reports `vault: false`. Do not point a workload at either.

## Build

From this directory, with the pinned toolchain:

```sh
cargo test --workspace --all-features --locked
```

`cargo test` checks that the workspace builds and that `/health` refuses to
claim a vault. It does not test a vault, because there is no vault.

The web shell, from `web/`:

```sh
pnpm install
pnpm check
pnpm dev
```

The API, from this directory:

```sh
cargo run -p navault-server
```

## What this is not

- Not a password manager you can log in to.
- Not a FIPS-validated module.
- Not post-quantum safe. No cryptographic algorithm is implemented here.
- Not a client for Bitwarden, 1Password, KeePass, Vault, OpenBao, Azure Key
  Vault, Dashlane, Proton Pass, Infisical, or Vaultwarden.

The first implementation has not started. Do not point a workload at this
repository.
