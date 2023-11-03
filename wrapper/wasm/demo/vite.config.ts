import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';
import { proxy } from './proxy';
import { proxy as dkls_local } from './proxy-local';

export default defineConfig({
    plugins: [sveltekit()],

    test: {
        include: ['src/**/*.{test,spec}.{js,ts}']
    },

    assetsInclude: ['**/*.wasm'],

    server: {
        host: '0.0.0.0',

        fs: {
            allow: ['../pkg']
        },

        proxy: process.env.DKLS_LOCAL ? dkls_local : proxy
    }
});
