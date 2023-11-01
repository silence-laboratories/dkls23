import { assertEquals }                        from 'https://deno.land/std@0.203.0/assert/mod.ts';
import { decodeHex, encodeHex }                from 'https://deno.land/std@0.203.0/encoding/hex.ts';
import * as base64                             from 'https://deno.land/x/base64/mod.ts';

import { genInstanceId, verifyingKey, KeygenSetup }         from './pkg/dkls_wasm.js';
import { dkgSetupMessage, init_dkg, join_dkg } from './pkg/dkls_wasm.js';
import { dsgSetupMessage, init_dsg, join_dsg } from './pkg/dkls_wasm.js';
import { start_dkg, start_dsg }                from './main.ts';
import { MsgRelayClient }                      from './js/msg-relay.js';

import { test } from './dkls_test.js';

const ENDPOINT = 'ws://localhost:8080';
// const ENDPOINT = 'ws://msg-relay.process.sl-demo.internal:8080';
// const ENDPOINT = 'wss://sl-demo.fly.dev/v1/msg-relay';


const SETUP_SK = decodeHex('b2012ec2ce6c7b64d58caf81f024a2a7e39ad3cb446973ff3ab363e8593f845d');


const PartySk = [
    decodeHex('a9130afb437107b5fa4142e56467ddee72fa5abdbc7fcd1f2abbfa8b5b04ddc7'),
    decodeHex('e9fc53eb8734468630d5e317bf12e6f11fa654c4caf3f5921a2082475b24558e'),
    decodeHex('fcdc915b33c7503f9fe2ed07700ec02cee6c55f22773bc39f14869df005e8c4b')
];

const PARTY_PK = [
    decodeHex('cfa1ff5424d14eb60614d7ddf65a32243d26ddf7000d10007853d7336395efe4'),
    decodeHex('8eb91174c3532ddf0a87eb1b17620282b36d9f5a535aeca22ab5d2f52b492d32'),
    decodeHex('2ac4da173f99dd2c48b6720ad3ceea62554fb8271b357fc8688b830510560aa0')
];

test('load', async () => {
    console.log('gen-instance-id', genInstanceId());
});

const dkgOpts = (instance: Uint8Array) => {
    return {
        instance,
        signingKey: SETUP_SK,
        threshold: 2,
        ttl: 30,
        parties: [
            {
                rank: 0,
                publicKey: PARTY_PK[0]
            },

            {
                rank: 0,
                publicKey: PARTY_PK[1]
            },

            {
                rank: 0,
                publicKey: PARTY_PK[2]
            }
        ]
    }
};

const dsgOpts = (instance: Uint8Array, publicKey: Uint8Array) => {
    return {
        instance,
        signingKey: SETUP_SK,
        publicKey,
        ttl: 3,
        message: instance,

        parties: [
            { publicKey: PARTY_PK[1] },
            { publicKey: PARTY_PK[2] }
        ]
    }
};

const dkg_all_cloud = async() => {
    let abort = new AbortController();
    let ws = await MsgRelayClient.connect(ENDPOINT + '/v1/msg-relay', abort.signal);

    try {
        let instance = genInstanceId();
        let setup_msg = dkgSetupMessage(dkgOpts(instance));

        ws.send(setup_msg);

        let resp = await Promise.all([
            start_dkg('http://localhost:8081', instance),
            start_dkg('http://localhost:8082', instance),
            start_dkg('http://localhost:8083', instance)
        ]);

        return base64.toUint8Array(resp[0].public_key);
    } finally {
        await ws.close();
    }
};

const dkg_web_cloud = async () => {
    let abort = new AbortController();
    let ws = await MsgRelayClient.connect(ENDPOINT + '/v1/msg-relay', abort.signal);

    try {
        let instance = genInstanceId();
        let setup_msg = dkgSetupMessage(dkgOpts(instance));

        ws.send(setup_msg);

        let p1 = join_dkg(
            encodeHex(instance),
            encodeHex(verifyingKey(SETUP_SK)),
            encodeHex(PartySk[0]),
            ENDPOINT + '/v1/msg-relay',
            encodeHex(genInstanceId()),
            async (setup: KeygenSetup) => {
                console.log('validate', setup); //, setup.rank(0), setup.verifyingKey(0));
                return true;
            }
        );

        let resp = await Promise.all([
            p1,
            start_dkg('http://localhost:8082', instance),
            start_dkg('http://localhost:8083', instance)
        ]);

        return resp[0];
    } finally {
        await ws.close();
    }
};

test('DKG all-cloud', async () => {
    await dkg_all_cloud();
});

test('DKG join-web + join-cloud', async () => {
    let abort = new AbortController();
    let ws = await MsgRelayClient.connect(ENDPOINT + '/v1/msg-relay', abort.signal);

    try {
        let instance = genInstanceId();
        let setup_msg = dkgSetupMessage(dkgOpts(instance));

        ws.send(setup_msg);

        let p1 = join_dkg(
            encodeHex(instance),
            encodeHex(verifyingKey(SETUP_SK)),
            encodeHex(PartySk[0]),
            ENDPOINT + '/v1/msg-relay',
            encodeHex(genInstanceId()),
            async (setup: KeygenSetup) => {
                console.log('validate', setup); //, setup.rank(0), setup.verifyingKey(0));
                return true;
            }
        );

        let resp = await Promise.all([
            p1,
            start_dkg('http://localhost:8082', instance),
            start_dkg('http://localhost:8083', instance)
        ]);

        let share = resp[0];
        console.log('resp', resp);
    } finally {
        await ws.close();
    }
});

test('DSG all-cloud', async () => {
    const pk = await dkg_all_cloud();

    let abort = new AbortController();
    let ws = await MsgRelayClient.connect(ENDPOINT + '/v1/msg-relay', abort.signal);

    try {
        let instance = genInstanceId();
        let setup_msg = dsgSetupMessage(dsgOpts(instance, pk));

        ws.send(setup_msg);

        let resp = await Promise.all([
            start_dsg('http://localhost:8082', instance),
            start_dsg('http://localhost:8083', instance)
        ]);

        let share = resp[0];
        console.log('resp', resp);
    } finally {
        await ws.close();
    }

});

test('DSG join-web + join-cloud', async () => {
    const share = await dkg_web_cloud();

    let abort = new AbortController();
    let ws = await MsgRelayClient.connect(ENDPOINT + '/v1/msg-relay', abort.signal);

    try {
        let instance = genInstanceId();
        let setup_msg = dsgSetupMessage(dsgOpts(instance, share.publicKey()));

        ws.send(setup_msg);

        let s2 = join_dsg(
            encodeHex(instance),
            encodeHex(verifyingKey(SETUP_SK)),
            encodeHex(PartySk[1]),
            ENDPOINT + '/v1/msg-relay',
            encodeHex(genInstanceId()),

            async (setup: any) => {
                console.log('DSG validator', setup, share);
                return share;
            }
        );

        let resp = await Promise.all([
            // start_dsg('http://localhost:8081', instance),
            s2, // start_dsg('http://localhost:8082', instance),
            start_dsg('http://localhost:8083', instance)
        ]);

        console.log('resp', resp);
    } finally {
        await ws.close();
    }

});
