<script lang="ts">
	/**
	 * The signed-out view: sign in.
	 *
	 * Account creation needs a session, so it lives on the signed-in page and
	 * not here. The password lives in component state only. It is never written
	 * to storage, never logged, and is cleared once the request settles.
	 */
	import { ApiError, describe, signIn } from '$lib/api';
	import { Button } from '$lib/components/ui/button/index.js';
	import * as Card from '$lib/components/ui/card/index.js';
	import { Input } from '$lib/components/ui/input/index.js';

	type Props = { onauthenticated: () => void };

	let { onauthenticated }: Props = $props();

	let email = $state('');
	let password = $state('');
	let busy = $state(false);
	let failure = $state<string | null>(null);

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

	function signInSubmit(event: SubmitEvent) {
		event.preventDefault();
		void submit();
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
</div>
