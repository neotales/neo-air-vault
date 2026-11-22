<script lang="ts">
	/**
	 * The signed-out view: sign in, or create an account.
	 *
	 * The password lives in component state only. It is never written to
	 * storage, never logged, and is cleared once the request settles. Nothing
	 * from a response is rendered except a created user's id and email.
	 */
	import { ApiError, describe, signIn, signUp, type User } from '$lib/api';
	import { Button } from '$lib/components/ui/button/index.js';
	import * as Card from '$lib/components/ui/card/index.js';
	import { Input } from '$lib/components/ui/input/index.js';

	type Props = { onauthenticated: () => void };

	let { onauthenticated }: Props = $props();

	let email = $state('');
	let password = $state('');
	let busy = $state(false);
	let failure = $state<string | null>(null);

	let newEmail = $state('');
	let newPassword = $state('');
	let creating = $state(false);
	let createFailure = $state<string | null>(null);
	let created = $state<User | null>(null);

	function fail(message: string) {
		failure = message;
	}

	async function submit() {
		if (busy) return;
		const address = email.trim();
		const candidate = password;
		if (address === '' || candidate === '') {
			fail('Email and password are required.');
			return;
		}

		busy = true;
		try {
			await signIn(address, candidate);
			email = '';
			failure = null;
			onauthenticated();
		} catch (error) {
			if (error instanceof ApiError && error.status === 401) {
				fail('Those credentials were not accepted.');
			} else {
				fail(describe(error));
			}
		} finally {
			password = '';
			busy = false;
		}
	}

	async function create() {
		if (creating) return;
		const address = newEmail.trim();
		const candidate = newPassword;
		if (address === '' || candidate === '') {
			createFailure = 'Email and password are required.';
			return;
		}

		creating = true;
		try {
			created = await signUp(address, candidate);
			createFailure = null;
		} catch (error) {
			createFailure = describe(error);
		} finally {
			newPassword = '';
			creating = false;
		}
	}

	function signInSubmit(event: SubmitEvent) {
		event.preventDefault();
		void submit();
	}

	function signUpSubmit(event: SubmitEvent) {
		event.preventDefault();
		void create();
	}
</script>

<div class="flex flex-col gap-6">
	<Card.Root>
		<Card.Header>
			<Card.Title>Sign in</Card.Title>
			<Card.Description>
				The session is a cookie this page cannot read. Nothing else is kept.
			</Card.Description>
		</Card.Header>
		<Card.Content>
			<form class="flex flex-col gap-3" onsubmit={signInSubmit}>
				<Input
					bind:value={email}
					type="email"
					aria-label="Email"
					placeholder="you@example.com"
					autocomplete="username"
					disabled={busy}
				/>
				<Input
					bind:value={password}
					type="password"
					aria-label="Password"
					placeholder="Password"
					autocomplete="current-password"
					disabled={busy}
				/>
				<div class="flex items-center justify-between gap-2">
					<Button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</Button>
				</div>
				{#if failure !== null}
					<p class="text-sm text-destructive" role="alert">{failure}</p>
				{/if}
			</form>
		</Card.Content>
	</Card.Root>

	<Card.Root>
		<Card.Header>
			<Card.Title>Create an account</Card.Title>
			<Card.Description>
				Creates a user. The id and email of the new user are shown; nothing else is.
			</Card.Description>
		</Card.Header>
		<Card.Content>
			<form class="flex flex-col gap-3" onsubmit={signUpSubmit}>
				<Input
					bind:value={newEmail}
					type="email"
					aria-label="New account email"
					placeholder="you@example.com"
					autocomplete="off"
					disabled={creating}
				/>
				<Input
					bind:value={newPassword}
					type="password"
					aria-label="New account password"
					placeholder="Password"
					autocomplete="new-password"
					disabled={creating}
				/>
				<div>
					<Button type="submit" variant="outline" disabled={creating}>
						{creating ? 'Creating…' : 'Create account'}
					</Button>
				</div>
				{#if createFailure !== null}
					<p class="text-sm text-destructive" role="alert">{createFailure}</p>
				{/if}
				{#if created !== null}
					<div class="rounded-lg border border-border p-3 text-sm">
						<p class="font-medium">Account created</p>
						<p class="text-muted-foreground">{created.email}</p>
						<code class="text-xs break-all text-muted-foreground">{created.id}</code>
						<p class="mt-2 text-muted-foreground">Sign in with it above.</p>
					</div>
				{/if}
			</form>
		</Card.Content>
	</Card.Root>
</div>
