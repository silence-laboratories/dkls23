import initDkls, { msg_relay_connect } from './pkg/dkls_wasm.js';

export const test = (name, f) => {
    Deno.test(name, async (t) => {
        await initDkls();
        return f(t);
    });
};

export { msg_relay_connect };
