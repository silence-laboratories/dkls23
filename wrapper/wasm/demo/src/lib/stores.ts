import { writable } from 'svelte/store';
import { type Keyshare } from 'dkls-wasm';

export type WalletInfo = {
    n: number,
    t: number
};

export const cloudPublicKeys = writable<Record<string, WalletInfo>>({});

export const keyshares = writable<Keyshare[]>([]);
