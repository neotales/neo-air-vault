# neo-air-vault

neo-air-vault is an early-stage credential and secrets-store project for
people, service accounts, and agents. The current server provides account,
group, and permission management; it does not store or encrypt secrets. The
process is still not a vault.

It uses Rust 1.100 and is licensed under MIT.

The server binary is `navault-server`. The CLI binary will be `navault`.
The human client is `web/`. Neither stores a secret. `/health` reports
`vault: false`. Do not point a workload at either.

## Build

From this directory, with the pinned toolchain:

```sh
cargo test --workspace --locked
```

This default test gate checks the workspace without enabling the `embed-ui`
fallback.

The web shell, from `web/`:

```sh
pnpm install
pnpm check
pnpm dev
```

The API, from this directory:

```sh
cargo run -p navault-server
cargo build -p navault-server --features embed-ui
```

On first run, when the store has no user, set `NAV_ADMIN_EMAIL` and
`NAV_ADMIN_PASSWORD` to bootstrap the administrator. `NAV_AUTH_KEY` is
optional; if provided it must be 64 hexadecimal characters. Otherwise the
server creates `auth.key` beside the database (`nav.sqlite` by default).

After signing in with `POST /sign-in`, a session-gated caller can create and
list users, groups, and permissions (`POST /sign-up`, `POST /groups`,
`POST /permissions`, `GET /users`, `GET /groups`, and `GET /permissions`).
Anonymous state-changing requests are refused except for `POST /sign-in`.
`/health` is not the only route. The process is still not a vault.

## What this is not

- Not a vault: callers can sign in and manage accounts, groups, and
  permissions, but the process does not store secrets.
- Not a FIPS-validated module.
- Not a post-quantum-secure vault.
- Not a client for Bitwarden, 1Password, KeePass, Vault, OpenBao, Azure Key
  Vault, Dashlane, Proton Pass, Infisical, or Vaultwarden.

Vault storage and secret-management functionality have not been implemented.
Do not point a workload at this repository.
