<script lang="ts">
	import { Badge } from '$lib/components/ui/badge/index.js';
	import { Button } from '$lib/components/ui/button/index.js';
	import * as Card from '$lib/components/ui/card/index.js';
	import * as Empty from '$lib/components/ui/empty/index.js';
	import { Separator } from '$lib/components/ui/separator/index.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const healthLabel = $derived(
		data.health.kind === 'not-a-vault'
			? 'API is up. It is not a vault.'
			: data.health.kind === 'down'
				? 'API is not running on 127.0.0.1:8787.'
				: 'API responded, but not with the health contract.'
	);

	const later = ['Unlock', 'Records', 'Principals', 'Audit'] as const;
</script>

<svelte:head>
	<title>neo-air-vault</title>
</svelte:head>

<main class="mx-auto flex min-h-screen w-full max-w-3xl flex-col gap-8 px-6 py-12">
	<header class="flex flex-col gap-3">
		<div class="flex items-center gap-3">
			<h1 class="text-2xl font-semibold tracking-tight">neo-air-vault</h1>
			<Badge variant="outline">not a vault</Badge>
		</div>
		<p class="text-sm text-balance text-muted-foreground">
			Human client for a credential store that is not built yet. This page does not unlock a vault,
			list records, or accept a secret.
		</p>
	</header>

	<Card.Root>
		<Card.Header>
			<Card.Title>API</Card.Title>
			<Card.Description>Loopback health only. No secret route exists.</Card.Description>
		</Card.Header>
		<Card.Content>
			<p>{healthLabel}</p>
		</Card.Content>
	</Card.Root>

	<Separator />

	<Empty.Root class="border">
		<Empty.Header>
			<Empty.Title>Nothing to open</Empty.Title>
			<Empty.Description>
				Unlock, records, principals, and audit wait until a person can open a vault and an agent can
				use a secret without receiving it.
			</Empty.Description>
		</Empty.Header>
		<Empty.Content>
			<div class="flex flex-wrap justify-center gap-2">
				{#each later as label (label)}
					<Button disabled variant="outline">{label}</Button>
				{/each}
			</div>
		</Empty.Content>
	</Empty.Root>
</main>
