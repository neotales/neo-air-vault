<script lang="ts">
	/**
	 * One card for a list whose rows are `{ id, name }`, with a create form.
	 * Used for groups and permissions; users have a different create body.
	 *
	 * Only `id` and `name` are rendered. Anything else the server returns is
	 * dropped by the API module before it reaches this component.
	 */
	import { ApiError, describe, type Named } from '$lib/api';
	import { Button } from '$lib/components/ui/button/index.js';
	import * as Card from '$lib/components/ui/card/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import { onMount } from 'svelte';

	type Props = {
		title: string;
		description: string;
		/** Singular noun used in the form label and the empty state. */
		noun: string;
		list: () => Promise<Named[]>;
		create: (name: string) => Promise<string>;
		/** The server answered 401: there is no session any more. */
		onunauthorized: () => void;
	};

	let { title, description, noun, list, create, onunauthorized }: Props = $props();

	let items = $state<Named[]>([]);
	let loading = $state(true);
	let busy = $state(false);
	let failure = $state<string | null>(null);
	let name = $state('');

	function fail(error: unknown) {
		if (error instanceof ApiError && error.status === 401) {
			onunauthorized();
			return;
		}
		failure = describe(error);
	}

	async function refresh() {
		try {
			items = await list();
			failure = null;
		} catch (error) {
			fail(error);
		} finally {
			loading = false;
		}
	}

	async function send() {
		if (busy) return;
		const proposed = name.trim();
		if (proposed === '') {
			failure = `A ${noun} needs a name.`;
			return;
		}

		busy = true;
		try {
			await create(proposed);
			name = '';
			await refresh();
		} catch (error) {
			fail(error);
		} finally {
			busy = false;
		}
	}

	function submit(event: SubmitEvent) {
		event.preventDefault();
		void send();
	}

	onMount(() => {
		void refresh();
	});
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>{title}</Card.Title>
		<Card.Description>{description}</Card.Description>
		<Card.Action>
			<Button variant="outline" size="sm" disabled={loading || busy} onclick={() => void refresh()}>
				Refresh
			</Button>
		</Card.Action>
	</Card.Header>
	<Card.Content class="flex flex-col gap-4">
		{#if loading}
			<p class="text-sm text-muted-foreground">Loading…</p>
		{:else if items.length === 0}
			<p class="text-sm text-muted-foreground">No {noun} yet.</p>
		{:else}
			<ul class="flex flex-col divide-y">
				{#each items as item (item.id)}
					<li
						class="flex flex-col gap-1 py-2 sm:flex-row sm:items-baseline sm:justify-between sm:gap-4"
					>
						<span class="text-sm font-medium">{item.name}</span>
						<code class="text-xs break-all text-muted-foreground">{item.id}</code>
					</li>
				{/each}
			</ul>
		{/if}

		<form class="flex flex-col gap-2 sm:flex-row" onsubmit={submit}>
			<Input
				bind:value={name}
				aria-label="{noun} name"
				placeholder="Name"
				autocomplete="off"
				disabled={busy}
			/>
			<Button type="submit" disabled={busy}>{busy ? 'Creating…' : `Create ${noun}`}</Button>
		</form>

		{#if failure !== null}
			<p class="text-sm text-destructive" role="alert">{failure}</p>
		{/if}
	</Card.Content>
</Card.Root>
