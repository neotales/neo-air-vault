# neo-air-vault web

SvelteKit, Tailwind CSS, and shadcn-svelte. pnpm. Node. This is the human
client. Its page signs in and manages users, groups, and permissions. It is
not a vault and it does not store a secret.

The API it may call is `navault-server` on `127.0.0.1:8787`. `/health`
reports whether the process is up and returns `vault: false`; it is not the
only route. The page also uses sign-in, session, and session-gated management
routes. The process does not store secrets.

```sh
pnpm install
pnpm check
pnpm dev
```

From the repository root, in another terminal:

```sh
cargo run -p navault-server
```

shadcn-svelte still imports `$lib`. That alias is set because the CLI emits
it. SvelteKit 3 also has `#lib`. Do not add a database or a secret form here
to make the empty states go away.
