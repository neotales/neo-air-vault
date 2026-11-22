<script lang="ts">
	import { describe, session, type Session } from '$lib/api';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import * as Card from '$lib/components/ui/card/index.js';
	import SignedIn from '$lib/components/signed-in.svelte';
	import SignedOut from '$lib/components/signed-out.svelte';
	import { parseHealth, type Health } from '$lib/health';
	import { onMount } from 'svelte';

	let health = $state<Health>({ kind: 'down' });
	let phase = $state<'checking' | Session>('checking');
	let failure = $state<string | null>(null);

	async function checkHealth() {
		try {
			const response = await fetch('/health', {
				headers: { accept: 'application/json' },
				redirect: 'error',
				signal: AbortSignal.timeout(750)
			});
			health = response.ok ? parseHealth(await response.json()) : { kind: 'mismatch' };
		} catch {
			health = { kind: 'down' };
		}
	}

	async function checkSession() {
		try {
			phase = await session();
			failure = null;
		} catch (error) {
			// An unreachable API is not a session. Show the form and say why.
			phase = 'out';
			failure = describe(error);
		}
	}

	onMount(() => {
		void checkHealth();
		void checkSession();
	});

	const healthLabel = $derived(
		health.kind === 'not-a-vault'
			? 'API is up. It is not a vault.'
			: health.kind === 'down'
				? 'API is not running on 127.0.0.1:8787.'
				: 'API responded, but not with the health contract.'
	);

	const healthBadge = $derived(
		health.kind === 'not-a-vault' ? 'API up' : health.kind === 'down' ? 'API down' : 'API mismatch'
	);

	const signedIn = $derived(phase === 'in');
</script>

<svelte:head>
	<title>neo-air-vault</title>
</svelte:head>

<main class="mx-auto flex min-h-screen w-full max-w-3xl flex-col gap-8 px-6 py-12">
	<header class="flex flex-col gap-3">
		<div class="flex flex-wrap items-center gap-3">
			<h1 class="text-2xl font-semibold tracking-tight">neo-air-vault</h1>
			<Badge variant="outline">not a vault</Badge>
			<Badge
				variant={health.kind === 'down'
					? 'destructive'
					: health.kind === 'mismatch'
						? 'secondary'
						: 'default'}
			>
				{healthBadge}
			</Badge>
			{#if signedIn}
				<Badge variant="secondary">signed in</Badge>
			{/if}
		</div>
		<p class="text-sm text-balance text-muted-foreground">
			Human client for a credential store that is not built yet. It signs in, and it lists and
			creates users, groups, and permissions. It does not unlock a vault and it never holds a
			secret.
		</p>
	</header>

	<Card.Root>
		<Card.Header>
			<Card.Title>API</Card.Title>
			<Card.Description>
				Loopback only. The page reaches it through same-origin paths.
			</Card.Description>
		</Card.Header>
		<Card.Content>
			<p>{healthLabel}</p>
		</Card.Content>
	</Card.Root>

	{#if phase === 'checking'}
		<p class="text-sm text-muted-foreground">Checking the session…</p>
	{:else if signedIn}
		<SignedIn
			onunauthorized={() => {
				phase = 'out';
			}}
		/>
	{:else}
		{#if failure !== null}
			<p class="text-sm text-destructive" role="alert">{failure}</p>
		{/if}
		<SignedOut
			onauthenticated={() => {
				phase = 'in';
				failure = null;
			}}
		/>
	{/if}
</main>
