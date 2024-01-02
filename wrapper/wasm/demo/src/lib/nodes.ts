import init, {
    genInstanceId,
    dkgSetupMessage,
    dsgSetupMessage,
    verifyingKey,
} from 'dkls-wasm';

import type {
    ClusterDef
} from './config.ts';

const start = async (endpoint: string, instance: Uint8Array): Promise<any> => {
    let resp = await fetch(endpoint, {
        method: 'POST',
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            instance: btoa(instance.reduce((s, b) => s + String.fromCharCode(b), ''))
        })
    });

    if (resp.status != 200) {
        console.log('resp status', endpoint, resp.status, await resp.text());
        throw new Error("status " + resp.status);
    }

    return await resp.json();
};

export async function startDkg(endpoint: string, instance: Uint8Array): Promise<any> {
    let resp = await start(endpoint + '/v1/keygen', instance);

    return resp;
}

export async function startDsg(endpoint: string, instance: Uint8Array): Promise<any> {
    let resp = await start(endpoint + '/v1/signgen', instance);

    return resp;
}

export function createKeygenSetupOpts(cluster: ClusterDef, participants: number, threshold: number, ttl: number = 10) {
    let instance = genInstanceId();
    return {
        instance,
        signingKey: cluster.setup.secretKey,
        threshold,
        ttl,
        parties: cluster.nodes.slice(0, participants).map(({ publicKey }) => {
            return { rank: 0, publicKey }
        })
    };
}

export function createKeygenSetup(cluster: ClusterDef, participants: number, threshold: number, ttl: number = 10) {
    let opts = createKeygenSetupOpts(cluster, participants, threshold, ttl);
    let setup = dkgSetupMessage(opts);

    return { setup, instance: opts.instance };
}

export function createSignSetupOpts(cluster: ClusterDef, publicKey: Uint8Array, message: Uint8Array, threshold: number) {
    let instance = genInstanceId();
    return {
        instance,
        message,
        publicKey,
        signingKey: cluster.setup.secretKey,
        parties: cluster.nodes.slice(0, threshold).map((n) => {
            return { rank: 0, publicKey: n.publicKey }
        }),
        ttl: 10
    };
}

export function createSignSetup(cluster: ClusterDef, publicKey: Uint8Array, message: Uint8Array, threshold: number) {
    let opts = createSignSetupOpts(cluster, publicKey, message, threshold);
    let setup = dsgSetupMessage(opts);

    return { setup, instance: opts.instance };
}

export function randomSeed(count: number = 32): Uint8Array {
    return window.crypto.getRandomValues(new Uint8Array(count));
}
