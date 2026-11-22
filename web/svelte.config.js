import adapterNode from '@sveltejs/adapter-node';
import adapterStatic from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

const embed = process.env.NAV_UI === 'static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: embed
			? adapterStatic({
					fallback: 'index.html',
					strict: false
				})
			: adapterNode()
	}
};

export default config;
