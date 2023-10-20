export const decodeHex = (s: string): Uint8Array => {
    let bytes = s.match(/[0-9A-Fa-f]{2}/g);
    if (!bytes) { throw new Error("bad hex string") }
    return Uint8Array.from(bytes.map((byte) => parseInt(byte, 16)));
}

export const encodeHex = (a: Uint8Array): string =>
    a.reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');
