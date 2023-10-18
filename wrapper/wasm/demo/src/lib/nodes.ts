import init, {
    genInstanceId,
    dkgSetupMessage,
    dsgSetupMessage,
    verifyingKey,
    dkg,
    dsg
} from 'dkls-wasm';

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

export function createKeygenSetup(cluster, threshold) {
    let instance = genInstanceId();
    let opts = {
        instance,
        signing_key: cluster.setup.secretKey,
        threshold,
        ttl: 10,
        parties: cluster.nodes.map((n) => {
            return { rank: 0, public_key: n.publicKey }
        })
    };

    let setup = dkgSetupMessage(opts);

    return { setup, instance };
}

export function createSignSetup(cluster, publicKey: Uin8Array, message: Uint8Array, threshold: number) {
    let instance = genInstanceId();
    let opts = {
        instance,
        message,
        public_key: publicKey,
        signing_key: cluster.setup.secretKey,
        parties: cluster.nodes.slice(0, threshold).map((n) => {
            return { rank: 0, public_key: n.publicKey }
        }),
        ttl: 10
    };

    let setup = dsgSetupMessage(opts);

    return { setup, instance };
}
