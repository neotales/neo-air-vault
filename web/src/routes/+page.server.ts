import { API_ORIGIN, parseHealth, type Health } from '$lib/health';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async (): Promise<{ health: Health }> => {
	try {
		const response = await fetch(`${API_ORIGIN}/health`, {
			headers: { accept: 'application/json' },
			redirect: 'error',
			signal: AbortSignal.timeout(750)
		});
		if (!response.ok) {
			return { health: { kind: 'mismatch' } };
		}
		return { health: parseHealth(await response.json()) };
	} catch {
		return { health: { kind: 'down' } };
	}
};
