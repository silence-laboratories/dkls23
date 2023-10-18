<script lang="ts">
 import '$lib/dkls';
 import { configs } from '$lib/config';
 import { createKeygenSetup, createSignSetup, startDkg, startDsg } from '$lib/nodes';
 import { decodeBase64 } from '$lib/base64';

 import {
     dkg,
     dsg,
     genInstanceId,
     verifyingKey,
     msg_relay_connect
 } from 'dkls-wasm';

 let generatingKeys = false;
 let threshold = 2;
 let partiesNumber = 3;

 $: validPartiesNum =
        +partiesNumber && partiesNumber > 2 && partiesNumber <= 5;
 $: validThreshold =
        +threshold && threshold > 1 && threshold < partiesNumber;

 let keygenStats = null;

 let signNum = 1;
 let signHashFn = "SHA256";
 let signMessage = "Something to sign";
 let generatingSign = false;

 let signStats = null;

 const handleGenKeys = async () => {
     let startTime = Date.now();
     generatingKeys = true;

     let cluster = await configs();

     cluster = cluster[1]; // TODO provide UI to select a cluster

     let { setup, instance } = await createKeygenSetup(cluster, threshold);

     let setupGen = Date.now();

     console.log('DKG setup gen', setupGen - startTime);

     let ws = await msg_relay_connect(cluster.setup.relay);

     let relayConnTime = Date.now();

     ws.send(setup);

     let genStart = Date.now();

     let resp = await Promise.all(cluster.nodes.map((n) => startDkg(n.endpoint, instance)));

     let genEnd = Date.now();

     keygenStats = resp;

     console.log('conn time', relayConnTime - setupGen);

     console.log('resp[0]', resp[0]);

     generatingKeys = false;
 };

 const handleSignGen = async () => {
     let startTime = Date.now();
     generatingSign = true;

     let cluster = await configs();

     cluster = cluster[1]; // TODO provide UI to select a cluster

     let { setup, instance } = await createSignSetup(
         cluster,
         decodeBase64(keygenStats[0].public_key),
         new TextEncoder().encode(signMessage),
         threshold
     );

     let setupGen = Date.now();

     console.log('DKG setup gen', setupGen - startTime, setup);


     let ws = await msg_relay_connect(cluster.setup.relay);

     let relayConnTime = Date.now();

     ws.send(setup);

     let genStart = Date.now();

     let resp = await Promise.all(cluster.nodes.slice(0, threshold).map((n) => startDsg(n.endpoint, instance)));

     let genEnd = Date.now();

     signStats = resp;

     generatingSign = false;
 };

</script>

<details open>
    <summary><strong> Introduction </strong></summary>

    <p>
        This page is a simple demo of the DKLs23-rs library. It allows
        you to run different variants of distributed key and signature
        generation against a small MPC network of 3 nodes. The network
        also contains a message relay service. All communications with
        the network go through a small proxy service that hosts this
        page, too.
    </p>

    <p>
        Participants communicate by publishing messages via the message
        relay service.
    </p>

    <p>
        The following sections will guide you through several
        examples. You could execute them and get some time metrics.
    </p>

    <p>
        The typical scheme of all protocols: prepare a "setup message"
        and publish it for all participants via the message relay
        service and then trigger execution of a protocol by making a
        special request to all network nodes.
    </p>
</details>

<details>
    <summary><strong>Key generation with "all cloud node" network</strong></summary>

    <p>
        The web application authorizes cloud nodes to generate a
        distributed key in this variant. All computations performed by
        cloud nodes and resulting shares of a generated key are stored
        in the cloud.
    </p>

    <div class="grid">
        <input
            type="text"
            name="threshold"
            placeholder="Threshold"
            aria-invalid={validThreshold ? "false" : "true"}
            bind:value={threshold}
        />
        <input
            type="text"
            name="participants"
            placeholder="Number of parties"
            aria-invalid={!validPartiesNum}
            bind:value={partiesNumber}
        />
        <button
            aria-busy={generatingKeys}
            on:click={handleGenKeys}
            disabled={!validPartiesNum || !validThreshold}
        >
            Generate key
        </button>
    </div>

    {#if keygenStats }
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Total time, ms</th>
                    <th>Wait time, ms</th>
                    <th>CPU time, ms</th>
                    <th>Bytes sent</th>
                    <th>Bytes received</th>
                </tr>
            </thead>
            <tbody>
                {#each keygenStats as n, idx}
                    <tr>
                        <td>{idx + 1}</td>
                        <td>{n.total_time}</td>
                        <td>{n.total_wait}</td>
                        <td>{n.total_time - n.total_wait}</td>
                        <td>{n.total_send}</td>
                        <td>{n.total_recv}</td>
                    </tr>
                {/each}
            </tbody>
        </table>

        <p>
            A few notes. <b> Total time </b> is a time from receiving an
            initial message from browser to finishing calculation of a key
            share. <b>Wait time</b> is how much time a node spent waiting
            for a message from other nodes out of <b>Total time</b>. The
            diffence of two is an estimation of CPU time.
        </p>

    {/if}
</details>

<details>
    <summary><strong>Signature generation</strong></summary>

    <p>
        Prepare a signature description message, publish it via the
        message relay service, and trigger a signature generation by
        network nodes.
    </p>

    <p>
        We could generate more than one signature in a row to get more
        realistic metrics of execution time. <b> TODO </b>
    </p>

    <div class="grid">
        <input
            type="text"
            placeholder="Enter messaege to sign"
            bind:value={signMessage}
        />
        <input type="number" bind:value={signNum} placeholder="N" />

        <button aria-busy={generatingSign} on:click={handleSignGen}>
            Generate signature
        </button>
    </div>

    {#if signStats }
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Total time, ms</th>
                    <th>Wait time, ms</th>
                    <th>CPU time, ms</th>
                    <th>Bytes sent</th>
                    <th>Bytes received</th>
                </tr>
            </thead>
            <tbody>
                {#each signStats as n, idx}
                    <tr>
                        <td>{idx + 1}</td>
                        <td>{n.total_time}</td>
                        <td>{n.total_wait}</td>
                        <td>{n.total_time - n.total_wait}</td>
                        <td>{n.total_send}</td>
                        <td>{n.total_recv}</td>
                    </tr>
                {/each}
            </tbody>
        </table>
    {/if}

</details>
