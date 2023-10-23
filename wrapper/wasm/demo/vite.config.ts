import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';
import { proxy } from './proxy';
// import { proxy } from './proxy-local';

export default defineConfig({
    plugins: [sveltekit()],

    test: {
        include: ['src/**/*.{test,spec}.{js,ts}']
    },

    assetsInclude: ['**/*.wasm'],

    server: {
        fs: {
            allow: ['../pkg']
        },

        proxy
    }
});
