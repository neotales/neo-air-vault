/**
 * Browser client for the `navault-server` API.
 *
 * Every path here is same-origin: in development Vite proxies these paths to
 * `127.0.0.1:8787`, and in the embedded build `navault-server` serves this page
 * itself. Keeping the calls relative is what keeps the session cookie
 * first-party.
 *
 * The session is the `neotales.session` cookie. This module never reads it,
 * stores it, or returns it. The only cookie it reads is `neotales.csrf`, which
 * the server sets without `HttpOnly` precisely so the page can copy it into
 * `x-csrf-token` on each POST.
 *
 * Response bodies are never kept on an error and never rendered wholesale: a
 * body can echo what was sent, and every list is projected onto a whitelist of
 * non-secret fields.
 */

/** Cookie the server sets for this page to copy into {@link CSRF_HEADER}. */
export const CSRF_COOKIE = 'neotales.csrf';

/** Header carrying the CSRF cookie value on every POST. */
export const CSRF_HEADER = 'x-csrf-token';

/** A user as the page may render it. No hash, digest, or secret field. */
export type User = { id: string; email: string };

/** A group or permission as the page may render it. */
export type Named = { id: string; name: string };

/** Whether a session is present. There is no third state: 401 means out. */
export type Session = 'in' | 'out';

/** A request that reached the server and came back with a non-success status. */
export class ApiError extends Error {
	readonly status: number;

	constructor(status: number) {
		super(`Request failed (${status}).`);
		this.name = 'ApiError';
		this.status = status;
	}
}

/** A success response whose body did not match the agreed shape. */
export class ContractError extends Error {
	constructor() {
		super('The server returned an unexpected body.');
		this.name = 'ContractError';
	}
}

/** A short, safe message for a failed request. Never echoes input or a body. */
export function describe(error: unknown): string {
	if (error instanceof ApiError) {
		if (error.status === 401) return 'Not signed in.';
		if (error.status === 403) return 'Blocked. The CSRF token was missing or stale.';
		return `Request failed (${error.status}).`;
	}
	if (error instanceof ContractError) return error.message;
	if (error instanceof DOMException && error.name === 'TimeoutError') {
		return 'The API did not answer in time.';
	}
	return 'The API could not be reached.';
}

function readCookie(name: string): string | null {
	const prefix = `${name}=`;
	for (const part of document.cookie.split(';')) {
		const entry = part.trim();
		if (entry.startsWith(prefix)) {
			return decodeURIComponent(entry.slice(prefix.length));
		}
	}
	return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function text(value: unknown): string | null {
	return typeof value === 'string' ? value : null;
}

async function get(path: string): Promise<Response> {
	return fetch(path, {
		credentials: 'include',
		headers: { accept: 'application/json' },
		redirect: 'error',
		signal: AbortSignal.timeout(5000)
	});
}

async function readJson(response: Response): Promise<unknown> {
	try {
		return await response.json();
	} catch {
		throw new ContractError();
	}
}

/**
 * GET `/session`, which also seeds the CSRF cookie. Ignored by
 * {@link postJson} when the cookie was already present.
 */
async function primeCsrf(): Promise<void> {
	try {
		await get('/session');
	} catch {
		// A POST without a token will report the real failure.
	}
}

async function post(path: string, body: Record<string, string>): Promise<Response> {
	let token = readCookie(CSRF_COOKIE);
	if (token === null) {
		await primeCsrf();
		token = readCookie(CSRF_COOKIE);
	}

	const headers: Record<string, string> = {
		accept: 'application/json',
		'content-type': 'application/json'
	};
	if (token !== null) {
		headers[CSRF_HEADER] = token;
	}

	return fetch(path, {
		method: 'POST',
		credentials: 'include',
		headers,
		body: JSON.stringify(body),
		redirect: 'error',
		signal: AbortSignal.timeout(5000)
	});
}

function parseUser(value: unknown): User {
	if (!isRecord(value)) throw new ContractError();
	const id = text(value.id);
	const email = text(value.email);
	if (id === null || email === null) throw new ContractError();
	return { id, email };
}

function parseUsers(value: unknown): User[] {
	if (!Array.isArray(value)) throw new ContractError();
	return value.map(parseUser);
}

function parseNamed(value: unknown): Named {
	if (!isRecord(value)) throw new ContractError();
	const id = text(value.id);
	const name = text(value.name);
	if (id === null || name === null) throw new ContractError();
	return { id, name };
}

function parseNamedList(value: unknown): Named[] {
	if (!Array.isArray(value)) throw new ContractError();
	return value.map(parseNamed);
}

/** GET `/session`. 401 is signed out; any other success is signed in. */
export async function session(): Promise<Session> {
	const response = await get('/session');
	if (response.status === 401) return 'out';
	if (!response.ok) throw new ApiError(response.status);
	return 'in';
}

/** POST `/sign-in`. 200 means the session cookie is set. */
export async function signIn(email: string, password: string): Promise<void> {
	const response = await post('/sign-in', { email, password });
	if (!response.ok) throw new ApiError(response.status);
}

/** POST `/sign-up`. 201 returns the created user; only id and email are kept. */
export async function signUp(email: string, password: string): Promise<User> {
	const response = await post('/sign-up', { email, password });
	if (!response.ok) throw new ApiError(response.status);

	const body = await readJson(response);
	if (!isRecord(body) || !isRecord(body.user)) throw new ContractError();
	return parseUser(body.user);
}

/** POST `/groups`. 201 returns the new id. */
export async function createGroup(name: string): Promise<string> {
	return createNamed('/groups', name);
}

/** POST `/permissions`. 201 returns the new id. */
export async function createPermission(name: string): Promise<string> {
	return createNamed('/permissions', name);
}

async function createNamed(path: string, name: string): Promise<string> {
	const response = await post(path, { name });
	if (!response.ok) throw new ApiError(response.status);

	const body = await readJson(response);
	if (!isRecord(body)) throw new ContractError();
	const id = text(body.id);
	if (id === null) throw new ContractError();
	return id;
}

/** GET `/users`. Renders id and email only. */
export async function listUsers(): Promise<User[]> {
	const response = await get('/users');
	if (!response.ok) throw new ApiError(response.status);
	return parseUsers(await readJson(response));
}

/** GET `/groups`. Renders id and name only. */
export async function listGroups(): Promise<Named[]> {
	const response = await get('/groups');
	if (!response.ok) throw new ApiError(response.status);
	return parseNamedList(await readJson(response));
}

/** GET `/permissions`. Renders id and name only. */
export async function listPermissions(): Promise<Named[]> {
	const response = await get('/permissions');
	if (!response.ok) throw new ApiError(response.status);
	return parseNamedList(await readJson(response));
}
