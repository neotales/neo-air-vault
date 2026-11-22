/** Loopback API the shell is allowed to call. It is not a vault. */
export const API_ORIGIN = 'http://127.0.0.1:8787';

export type Health = { kind: 'down' } | { kind: 'mismatch' } | { kind: 'not-a-vault' };

/**
 * Accept only the health contract: `{ "status": "ok", "vault": false }`.
 * Any other shape, including a claim that a vault exists, is a mismatch.
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
