import initDkls from './pkg/dkls_wasm.js';

const loaded = await initDkls();

export default await loaded;
