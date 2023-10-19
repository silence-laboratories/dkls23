import initDkls, { join_dkg, init_dkg, dsg, genInstanceId, msg_relay_connect } from './pkg/dkls_wasm.js';

export const test = (name, f) => {
    Deno.test(name, async (t) => {
        await initDkls();
        return f(t);
    });
};

export { init_dkg, join_dkg, dsg, genInstanceId, msg_relay_connect };
