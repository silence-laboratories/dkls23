import { assertEquals } from "https://deno.land/std@0.203.0/assert/mod.ts";

import { MsgRelayClient, randomMsgId } from './msg-relay.js';

import { test, msg_relay_connect } from '../dkls_test.js';

const ENDPOINT = 'ws://localhost:8080/v1/msg-relay';


const genMsg = (payloadSize: number, ttl: number): Uint8Array => {
    let size = payloadSize + 32 + 4 + 32;
    let buf = new ArrayBuffer(size);

    new DataView(buf).setUint32(32, ttl, true);

    let id = new Uint8Array(buf, 0, 32);

    crypto.getRandomValues(id);

    const msg = new Uint8Array(buf);

    return msg;
}

const msgId = (msg: Uint8Array): Uint8Array => {
    return new Uint8Array(msg, 0, 32);
}

const msgHdr = (msg: Uint8Array): Uint8Array => {
    return new Uint8Array(msg.buffer, 0, 32 + 4);
}

const msgEq = (m1: Uint8Array, m2: Uint8Array): Boolean => {
    return m1.length == m2.length && m1.every((b, idx) => m2[b] === idx);
}

test('connect MsgRelayClient', async () => {
    let abort = new AbortController();
    let client = await msg_relay_connect(ENDPOINT, abort.signal);

    await client.close();
});

test('connect', async () => {
    let abort = new AbortController();
    let relay = await MsgRelayClient.connect(ENDPOINT, abort.signal);
    let msg = genMsg(100, 10);

    relay.send(msg);

    await relay.close();

    await new Promise((resolve) => setTimeout(resolve, 0));
});

test('send/recv', async () => {
    let abort = new AbortController();

    let r1 = await MsgRelayClient.connect(ENDPOINT, abort.signal);
    let msg = genMsg(100, 10);

    r1.send(msg);

    let r2 = await MsgRelayClient.connect(ENDPOINT, abort.signal);

    r2.send(msgHdr(msg));

    let msg2 = await r2.next();

    await r2.close();
    await r1.close();

    assertEquals(msg, msg2);
});

test('random msg-id', () => {
    let id = randomMsgId();
});
