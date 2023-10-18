export const proxy = {
    '^/party-0/.*': {
        target: 'http://dkls-party-0.process.sl-demo.internal:8080',
        rewrite: (path) => path.replace(/^\/party-0/, '')
    },

    '^/party-1/.*': {
        target: 'http://dkls-party-1.process.sl-demo.internal:8080',
        rewrite: (path) => path.replace(/^\/party-1/, '')
    },

    '^/party-2/.*': {
        target: 'http://dkls-party-2.process.sl-demo.internal:8080',
        rewrite: (path) => path.replace(/^\/party-2/, '')
    },

    '/v1/msg-relay': {
        target: 'ws://msg-relay.process.sl-demo.internal:8080',
        ws: true
    }
};
