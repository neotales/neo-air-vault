# neo-air-vault web

SvelteKit, Tailwind CSS, and shadcn-svelte. pnpm. Node. This is the human
client. It is not a vault and it does not store a secret.

The API it may call is `navault-server` on `127.0.0.1:8787`. The only
route is `/health`. A response of `{ "status": "ok", "vault": false }` means
the process is up. It does not mean a vault exists.

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
