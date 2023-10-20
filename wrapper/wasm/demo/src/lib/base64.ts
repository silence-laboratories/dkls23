export const decodeBase64 = (b64) => Uint8Array.from(atob(b64), b => b.charCodeAt(0));

export const encodeBase64 = (b) => btoa(String.fromCodePoint.apply(null, b));
