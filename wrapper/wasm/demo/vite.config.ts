import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';
import { proxy } from './proxy';

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
        // proxy: {
        //     '^/party-0/.*': {
        //         target: 'http://dkls-party-0.process.sl-demo.internal:8080',
        //         rewrite: (path) => path.replace(/^\/party-0/, '')
        //     },

        //     '^/party-1/.*': {
        //         target: 'http://dkls-party-1.process.sl-demo.internal:8080',
        //         rewrite: (path) => path.replace(/^\/party-1/, '')
        //     },

        //     '^/party-2/.*': {
        //         target: 'http://dkls-party-2.process.sl-demo.internal:8080',
        //         rewrite: (path) => path.replace(/^\/party-2/, '')
        //     },

        //     '/v1/msg-relay': {
        //         target: 'ws://msg-relay.process.sl-demo.internal:8080',
        //         ws: true
        //     }
        // }
    }
});
