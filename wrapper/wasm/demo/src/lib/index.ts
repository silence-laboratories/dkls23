// place files you want to import through the `$lib` alias in this folder.

import init from 'dkls-wasm';
export * as dkls from 'dkls-wasm';

import wasmUrl from 'dkls-wasm/dkls_wasm_bg.wasm?url';

console.log('wasmUr', wasmUrl);

init(wasmUrl);
