////////////////////////////////////////////////////////////////////////////////
function msg_id(msg) {
    return new Uint8Array(msg.buffer, 0, 32);
}

function arrEq(a, b) {
  if (a.length !== b.length) {
        return false
    }

    return a.every((value, index) => value === b[index])
}

function msg_id_eq(m1, m2) {
    return arrEq(msg_id(m1), msg_id(m2));
}

export function randomMsgId() {
    let id = new Uint8Array(32);

    crypto.getRandomValues(id);

    return id;
}

function getArrayBuffer(evt) {
    if (evt.data instanceof ArrayBuffer) {
        return Promise.resolve(evt.data);
    } else if (evt.data instanceof Blob) {
        console.log('Blob');
        let data = evt.data.arrayBuffer();
        return data;
    } else {
        return Promise.resolve(null);
    }
}

export class MsgRelayClient {
    constructor(ws) {
        this.ws = ws;
        this.inBuf = [];
        this.waiter = null;
    }

    async close () {
        if (this.ws.readyState == 3) {
            return Promise.resolved(true);
        }

        return new Promise((resolve) => {
            this.ws.onclose = () => {
                // console.log('closed');
                resolve(true);
            };

            this.ws.close();
        });
    }

    send(msg) {
        this.ws.send(msg);
    }

    next() {
        if (this.inBuf.length > 0) {
            return Promise.resolve(this.inBuf.pop());
        } else {
            return new Promise((resolve) => {
                this.waiter = resolve;
            });
        }
    }

    static async connect(endpoint) {
        return new Promise(async (resolve, reject) => {
            let ws = new WebSocket(endpoint);
            let relay = new MsgRelayClient(ws);

            ws.binaryType = "arraybuffer";

            ws.onmessage = (evt) => {
                getArrayBuffer(evt).then((data) => {
                    if (!data) {
                        return;
                    }

                    let msg = new Uint8Array(data);

                    let waiter = relay.waiter;

                    relay.waiter = null;

                    if (waiter) {
                        waiter(msg);
                    } else {
                        relay.inBuf.push(msg);
                    }
                });
            }

            ws.onopen = (evt) => {
                ws.onerror = null;
                resolve(relay);
            }

            ws.onerror = (evt) => {
                reject(evt);
            }
        })
    }
}
