import tailwindcss from '@tailwindcss/vite';
import adapterNode from '@sveltejs/adapter-node';
import adapterStatic from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

/** The embedded build is a static site served by navault-server. */
const embed = process.env.NAV_UI === 'static';

const adapter = embed ? adapterStatic({ fallback: 'index.html', strict: false }) : adapterNode();

/** The loopback API. Only the dev server and preview talk to it directly. */
const API_TARGET = 'http://127.0.0.1:8787';

/**
 * Paths the page calls as same-origin relative URLs. The proxy keeps the
 * session cookie first-party on whatever host and port serves the page.
 */
const API_PATHS = ['/health', '/session', '/sign-in', '/sign-up', '/users', '/groups', '/permissions'];

const apiProxy = Object.fromEntries(API_PATHS.map((path) => [path, { target: API_TARGET }]));

export default defineConfig({
	plugins: [
		tailwindcss(),
		sveltekit({
			alias: {
				$lib: 'src/lib',
				'$lib/*': 'src/lib/*'
			},
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			adapter
		})
	],
	server: { proxy: apiProxy },
	preview: { proxy: apiProxy }
});
