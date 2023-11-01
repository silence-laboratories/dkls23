<script lang="ts">
 import '$lib/dkls';

 import { default as Intro }            from '$lib/components/Intro.svelte';
 import { default as TimeMetrics }      from '$lib/components/TimeMetrics.svelte';
 import { default as SummaryTimes }     from '$lib/components/SummaryTimes.svelte';
 import { configs, wsUrl }              from '$lib/config';
 import { decodeBase64, encodeBase64 }  from '$lib/base64';
 import { encodeHex }                   from '$lib/hex';

 import {
     createKeygenSetup,
     createKeygenSetupOpts,
     createSignSetup,
     startDkg,
     startDsg
 } from '$lib/nodes';

 import {
     init_dkg,
     join_dkg,
     join_dsg,
     genInstanceId,
     verifyingKey,
     msg_relay_connect,
     createAbortMessage
 } from 'dkls-wasm';

 let generatedPublicKey = null;
 let currentInstanceId = null;
 let generatingKeys = false;
 let threshold = 2;
 let partiesNumber = 3;
 let joinPartyId = 1;
 let joinInstanceId = null;


 $: validPartiesNum =
        +partiesNumber && partiesNumber > 2 && partiesNumber <= 5;
 $: validThreshold =
        +threshold && threshold > 1 && threshold < partiesNumber;

 let keygenStats = null;
 let keygenTimes = {};

 let keygenWebStats = null;
 let keygenWebTimes = {};

 let signNum = 1;
 let signHashFn = "SHA256";
 let signMessage = "Something to sign";
 let generatingSign = false;

 let signStats = null;
 let signTimes = {};



 const handleGenKeysWeb = async () => {
     let startTime = Date.now();

     generatingKeys = true;

     let cluster = await configs();

     cluster = cluster[1]; // TODO provide UI to select a cluster

     try {
         let opts = await createKeygenSetupOpts(cluster, threshold);

         let setupGen = Date.now();

         console.log('DKG setup gen', setupGen - startTime);

         let msgRelayUrl = wsUrl(cluster.setup.relay);

         let genStart = Date.now();

         let web_party = init_dkg(
             opts,
             encodeHex(cluster.nodes[0].secretKey),
             msgRelayUrl,
             encodeHex(genInstanceId()) // seed
         );

         let resp = await Promise.all([
             web_party,
             ...cluster.nodes.slice(1).map((n) => startDkg(n.endpoint, opts.instance))
         ]);

         let genEnd = Date.now();

         console.log('resp', resp);

         console.log('pk', resp[0].publicKey(), encodeBase64(resp[0].publicKey()));

         keygenWebStats = resp;

         keygenWebTimes = {
             totalTime: genEnd - startTime,
             setupGenTime: setupGen - startTime,
         };
     } finally {
         generatingKeys = false;
     }
 };


 const handleInitGenKeyAllWeb = async () => {
     let startTime = Date.now();
     generatingKeys = true;

     let cluster = await configs();

     cluster = cluster[1]; // TODO provide UI to select a cluster

     let opts = await createKeygenSetupOpts(cluster, threshold, 1000);

     let setupGen = Date.now();

     console.log('DKG setup gen', setupGen - startTime);

     let msgRelayUrl = wsUrl(cluster.setup.relay);

     let genStart = Date.now();

     let web_party = init_dkg(
         opts,
         encodeHex(cluster.nodes[0].secretKey),
         msgRelayUrl,
         encodeHex(genInstanceId()) // seed
     );

     currentInstanceId = opts.instance;

     await navigator.clipboard.writeText(encodeHex(currentInstanceId));

     let share = await web_party;

     console.log(share, encodeHex(share.publicKey()));

     generatedPublicKey = encodeHex(share.publicKey());

     currentInstanceId = null;

     generatingKeys = false;
 };

 const handleJoinGenKeyAllWeb = async () => {
     let startTime = Date.now();
     generatingKeys = true;

     let cluster = await configs();

     cluster = cluster[1]; // TODO provide UI to select a cluster

     let msgRelayUrl = wsUrl(cluster.setup.relay);

     let genStart = Date.now();

     let web_party = join_dkg(
         joinInstanceId,
         encodeHex(cluster.setup.publicKey),
         encodeHex(cluster.nodes[+joinPartyId].secretKey),
         msgRelayUrl,
         encodeHex(genInstanceId()) // seed
     );

     let share = await web_party;

     let endTime = Date.now();

     console.log(share, encodeHex(share.publicKey()));

     generatedPublicKey = encodeHex(share.publicKey());

     generatingKeys = false;
 };

 const handleKeygenAbort = async () => {
     console.log('abort keygen');

     let cluster = await configs();

     cluster = cluster[1]; // TODO provide UI to select a cluster

     let abort_msg = createAbortMessage(
         joinInstanceId,
         10000,
         encodeHex(cluster.nodes[+joinPartyId].secretKey)
     );

     let abort = new AbortController();
     let ws = await msg_relay_connect(wsUrl(cluster.setup.relay), abort.signal);

     let relayConnTime = Date.now();

     ws.send(abort_msg);
     ws.close();

 };
</script>

<Intro />

<details>
    <summary>
        <strong>Key generation with a web party + rest of cloud nodes</strong>
    </summary>

    <p>
        This example will generate a distributed key, but this web
        application will execute one participant and the other two by
        the cloud nodes.
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
            on:click={handleGenKeysWeb}
            disabled={!validPartiesNum || !validThreshold}
        >
            Generate key
        </button>
    </div>

    <SummaryTimes {... keygenWebTimes} />
    <TimeMetrics stats={keygenWebStats && keygenWebStats.slice(1)} />

</details>

<details>
    <summary>
        <strong>Begin key generation with all web parties</strong>
    </summary>

    <p>
        To initiate the generation of a key, one of the parties has to
        define the parameters of the key, publish the "setup message"
        via the message relay service, and share the "instance ID"
        with all other parties. This "instance ID" serves as a
        one-time password for parties to participate in some
        particular execution of an MPC protocol.
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
            on:click={handleInitGenKeyAllWeb}
            disabled={!validPartiesNum || !validThreshold}
        >
            Init key generation
        </button>
    </div>

    {#if currentInstanceId}
        <p>
            Share instance ID with other two parties in order to
            finish generation of a distributed key.
        </p>

        <div>
            {encodeHex(currentInstanceId)}
        </div>
    {/if}

    {#if generatedPublicKey}
        <div>
            Public Key: {generatedPublicKey}
        </div>
    {/if}

</details>

<details>
    <summary>
        <strong>Join others to generate a distributed key</strong>
    </summary>

    <p>
        A person who initiated the generation of a distributed key
        should share with you an instance ID. In the second field,
        enter participant ID: number 1 or 2. You and another person
        joining the key generation should use different participant IDs.
    </p>

    <div class="grid">
        <input
            type="text"
            name="instanceId"
            placeholder="Instance ID"
            bind:value={joinInstanceId}
        />
    </div>

    <div class="grid">
        <input
            type="text"
            name="joinPartyId"
            placeholder="ID of the participant"
            aria-invalid={!validPartiesNum}
            bind:value={joinPartyId}
        />

        <button
            aria-busy={generatingKeys}
            on:click={handleJoinGenKeyAllWeb}
        >
            Join
        </button>

        <button
            aria-busy={generatingKeys}
            on:click={handleKeygenAbort}
        >
            Abort
        </button>
    </div>

    {#if generatedPublicKey}
        <div>
            Public key: {generatedPublicKey}
        </div>
    {/if}
</details>
