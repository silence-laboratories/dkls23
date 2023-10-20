import polka from 'polka';
import httpProxy from 'http-proxy';

import { proxy } from './proxy.js';
import { handler } from './build/handler.js';

let app = polka();


for (const pattern in proxy) {
    let opts = proxy[pattern];
    let handle = httpProxy.createProxyServer(opts);

    if (opts.ws) {
        app.get(pattern, handle.ws);
    } else {
        app.post(pattern, handle.web);
    }

    console.log('opts', pattern, opts, handle);
}

app
    .use(handler)
    .listen(3000, () => {
        console.log(`> Running on localhost:3000`);
    });
