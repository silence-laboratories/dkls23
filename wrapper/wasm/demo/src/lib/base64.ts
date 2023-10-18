export const decodeBase64 = (b64) => Uint8Array.from(atob(b64), b => b.charCodeAt(0));
