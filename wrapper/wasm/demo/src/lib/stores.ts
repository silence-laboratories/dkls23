import { writable } from 'svelte/store';
import { type Keyshare } from 'dkls-wasm';


export const cloudPublicKeys = writable<string[]>([]);

export const keyshares = writable<Keyshare[]>([]);
