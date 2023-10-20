import { assertEquals } from "https://deno.land/std@0.203.0/assert/mod.ts";
import { decodeHex, encodeHex } from "https://deno.land/std@0.203.0/encoding/hex.ts";
import * as base64 from "https://deno.land/x/base64/mod.ts";
import { genInstanceId, dkgSetupMessage, verifyingKey, dkg, dsg } from './pkg/dkls_wasm.js';

import { start_dkg } from './main.ts';
import { MsgRelayClient } from './js/msg-relay.js';

import { test } from './dkls_test.js';

const ENDPOINT = 'ws://localhost:8080';
//const ENDPOINT = 'ws://msg-relay.process.sl-demo.internal:8080';
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

test('create DKG setup message', async () => {
    let instance = genInstanceId();
    let opts = {
        instance,
        signing_key: SETUP_SK,
        threshold: 2,
        ttl: 10,
        parties: [
            {
                rank: 0,
                public_key: PARTY_PK[0]
            },

            {
                rank: 0,
                public_key: PARTY_PK[1]
            },

            {
                rank: 0,
                public_key: PARTY_PK[2]
            }
        ]
    };

    let setup_msg = dkgSetupMessage(opts);

    console.log('setup', setup_msg);

    let ws = await MsgRelayClient.connect(ENDPOINT + '/v1/msg-relay');
    ws.send(setup_msg);

    // let p1 = dkg(
    //     encodeHex(instance),
    //     encodeHex(verifyingKey(SETUP_SK)),
    //     encodeHex(PartySk[0]),
    //     ENDPOINT + '/v1/msg-relay',
    //     encodeHex(genInstanceId())
    // );

    // let p2 = dkg(
    //     encodeHex(instance),
    //     encodeHex(verifyingKey(SETUP_SK)),
    //     encodeHex(PartySk[1]),
    //     ENDPOINT + '/v1/msg-relay',
    //     encodeHex(genInstanceId())
    // );

    // let p3 = dkg(
    //     encodeHex(instance),
    //     encodeHex(verifyingKey(SETUP_SK)),
    //     encodeHex(PartySk[2]),
    //     ENDPOINT + '/v1/msg-relay',
    //     encodeHex(genInstanceId())
    // );

    // console.log('stat p1 - loc, p2,p3 remote');

    let resp = await Promise.all([
        start_dkg('http://localhost:8080/party-0', instance),
        start_dkg('http://localhost:8080/party-1', instance),
        start_dkg('http://localhost:8080/party-2', instance)
        // start_dkg('http://localhost:8081', instance),
        // start_dkg('http://localhost:8082', instance),
        // start_dkg('http://localhost:8083', instance)
    ]);

    let pk = resp[0];
    console.log('resp', resp);

    await ws.close();
});
