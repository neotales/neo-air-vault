export type Health = { kind: 'down' } | { kind: 'mismatch' } | { kind: 'not-a-vault' };

/**
 * Accept only the health contract: `{ "status": "ok", "vault": false }`.
 * Any other shape, including a claim that a vault exists, is a mismatch.
 *
 * Callers request `/health` as a same-origin relative path; Vite proxies it in
 * development and `navault-server` serves the page itself in the embedded build.
 */
export function parseHealth(value: unknown): Exclude<Health, { kind: 'down' }> {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		return { kind: 'mismatch' };
	}

	const record = value as Record<string, unknown>;
	const keys = Object.keys(record);
	if (keys.length !== 2 || record.status !== 'ok' || record.vault !== false) {
		return { kind: 'mismatch' };
	}

	return { kind: 'not-a-vault' };
}
