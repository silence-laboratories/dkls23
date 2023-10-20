import * as base64 from "https://deno.land/x/base64/mod.ts";

import './load-dkls.ts';

const start = async (endpoint: string, instance: Uint8Array): Promise<any> => {
    let resp = await fetch(endpoint, {
        method: 'POST',
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            instance: base64.fromUint8Array(instance)
        })
    });

    if (resp.status != 200) {
        console.log('resp status', endpoint, resp.status, await resp.text());
        throw new Error("status " + resp.status);
    }

    return await resp.json();
};

export async function start_dkg(endpoint: string, instance: Uint8Array): Promise<any> {
    let resp = await start(endpoint + '/v1/keygen', instance);

    return resp;
}

export async function start_dsg(endpoint: string, instance: Uint8Array): Promise<any> {
    let resp = await start(endpoint + '/v1/signgen', instance);

    return resp;
}
