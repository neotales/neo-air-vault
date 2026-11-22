<script lang="ts">
	/**
	 * The signed-in view: users, groups, and permissions.
	 *
	 * Each section lists rows and creates one. A 401 from any call means the
	 * session is gone, so the page returns to the sign-in form. Rows are the
	 * projected `{ id, email }` or `{ id, name }` fields only.
	 */
	import {
		ApiError,
		describe,
		createGroup,
		createPermission,
		listGroups,
		listPermissions,
		listUsers,
		signUp,
		type User
	} from '$lib/api';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import { Button } from '$lib/components/ui/button/index.js';
	import * as Card from '$lib/components/ui/card/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import NameCard from './name-card.svelte';
	import { onMount } from 'svelte';

	type Props = { onunauthorized: () => void };

	let { onunauthorized }: Props = $props();

	let users = $state<User[]>([]);
	let loading = $state(true);
	let busy = $state(false);
	let failure = $state<string | null>(null);
	let created = $state<User | null>(null);
	let email = $state('');
	let password = $state('');

	function fail(error: unknown) {
		if (error instanceof ApiError && error.status === 401) {
			onunauthorized();
			return;
		}
		failure = describe(error);
	}

	async function refresh() {
		try {
			users = await listUsers();
			failure = null;
		} catch (error) {
			fail(error);
		} finally {
			loading = false;
		}
	}

	async function create() {
		if (busy) return;
		const address = email.trim();
		const candidate = password;
		if (address === '' || candidate === '') {
			failure = 'Email and password are required.';
			return;
		}

		busy = true;
		try {
			created = await signUp(address, candidate);
			email = '';
			failure = null;
			await refresh();
		} catch (error) {
			fail(error);
		} finally {
			password = '';
			busy = false;
		}
	}

	function submit(event: SubmitEvent) {
		event.preventDefault();
		void create();
	}

	onMount(() => {
		void refresh();
	});
</script>

<div class="flex flex-col gap-6">
	<Card.Root>
		<Card.Header>
			<Card.Title>Users</Card.Title>
			<Card.Description>Id and email only. No hash or digest is read or shown.</Card.Description>
			<Card.Action>
				<Button
					variant="outline"
					size="sm"
					disabled={loading || busy}
					onclick={() => void refresh()}
				>
					Refresh
				</Button>
			</Card.Action>
		</Card.Header>
		<Card.Content class="flex flex-col gap-4">
			{#if loading}
				<p class="text-sm text-muted-foreground">Loading…</p>
			{:else if users.length === 0}
				<p class="text-sm text-muted-foreground">No users yet.</p>
			{:else}
				<ul class="flex flex-col divide-y">
					{#each users as user (user.id)}
						<li
							class="flex flex-col gap-1 py-2 sm:flex-row sm:items-baseline sm:justify-between sm:gap-4"
						>
							<span class="text-sm font-medium">{user.email}</span>
							<code class="text-xs break-all text-muted-foreground">{user.id}</code>
						</li>
					{/each}
				</ul>
			{/if}

			<form class="flex flex-col gap-2 sm:flex-row" onsubmit={submit}>
				<Input
					bind:value={email}
					type="email"
					aria-label="New user email"
					placeholder="you@example.com"
					autocomplete="off"
					disabled={busy}
				/>
				<Input
					bind:value={password}
					type="password"
					aria-label="New user password"
					placeholder="Password"
					autocomplete="new-password"
					disabled={busy}
				/>
				<Button type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create user'}</Button>
			</form>

			{#if failure !== null}
				<p class="text-sm text-destructive" role="alert">{failure}</p>
			{/if}

			{#if created !== null}
				<div class="flex flex-wrap items-center gap-2 rounded-lg border border-border p-3 text-sm">
					<Badge variant="secondary">User created</Badge>
					<span class="font-medium">{created.email}</span>
					<code class="text-xs break-all text-muted-foreground">{created.id}</code>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<NameCard
		title="Groups"
		noun="group"
		description="Id and name only. Permissions are not attached here."
		list={listGroups}
		create={createGroup}
		{onunauthorized}
	/>

	<NameCard
		title="Permissions"
		noun="permission"
		description="Id and name only. Grants are not made here."
		list={listPermissions}
		create={createPermission}
		{onunauthorized}
	/>
</div>
