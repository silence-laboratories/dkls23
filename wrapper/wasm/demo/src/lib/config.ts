import { loaded, verifyingKey } from './dkls';
import { decodeHex } from './hex';

export type SetupDefs = {
    relay: string,
    secretKey: Uint8Array,
    publicKey: Uint8Array
};

export type NodeDef = {
    endpoint: string,
    publicKey: Uint8Array,
    secretKey: Uint8Array
};

export type ClusterDef = {
    setup: SetupDefs,
    nodes: Array<NodeDef>,

}

export const clusterConfig = async (): Promise<ClusterDef> => {
    await loaded;

    return {
        setup: {
            relay: '/v1/msg-relay',
            secretKey: decodeHex('b2012ec2ce6c7b64d58caf81f024a2a7e39ad3cb446973ff3ab363e8593f845d'),
            publicKey: verifyingKey(decodeHex('b2012ec2ce6c7b64d58caf81f024a2a7e39ad3cb446973ff3ab363e8593f845d'))
        },

        // THIS IS NOT A REAL PRODUCT, THIS IS A DEMO!
        nodes: [
            {
                endpoint: '/party-0',
                publicKey: decodeHex('cfa1ff5424d14eb60614d7ddf65a32243d26ddf7000d10007853d7336395efe4'),
                secretKey: decodeHex('a9130afb437107b5fa4142e56467ddee72fa5abdbc7fcd1f2abbfa8b5b04ddc7')
            },

            {
                endpoint: '/party-1',
                publicKey: decodeHex('8eb91174c3532ddf0a87eb1b17620282b36d9f5a535aeca22ab5d2f52b492d32'),
                secretKey: decodeHex('e9fc53eb8734468630d5e317bf12e6f11fa654c4caf3f5921a2082475b24558e')
            },

            {
                endpoint: '/party-2',
                publicKey: decodeHex('2ac4da173f99dd2c48b6720ad3ceea62554fb8271b357fc8688b830510560aa0'),
                secretKey: decodeHex('fcdc915b33c7503f9fe2ed07700ec02cee6c55f22773bc39f14869df005e8c4b')
            }
        ]
    }
};

export const wsUrl = (path) => {
    if (path.startsWith('ws://') || path.startsWith('wss://')) {
        return path;
    }

    // https: => wss:
    // http:  => ws:
    const proto = window.location.protocol.replace('http', 'ws');

    return proto + window.location.host + path;
}
