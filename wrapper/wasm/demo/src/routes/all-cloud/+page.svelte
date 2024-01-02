<script lang="ts">
 import { default as TimeMetrics }      from '$lib/components/TimeMetrics.svelte';
 import { default as SummaryTimes }     from '$lib/components/SummaryTimes.svelte';
 import { clusterConfig, wsUrl }        from '$lib/config';
 import { decodeBase64, encodeBase64 }  from '$lib/base64';
 import { encodeHex }                   from '$lib/hex';
 import { cloudPublicKeys }             from '$lib/stores';
 import { msg_relay_connect }           from 'dkls-wasm';

 import {
     createKeygenSetup,
     createSignSetup,
     startDkg,
     startDsg
 } from '$lib/nodes';

 let generatingKeys = false;
 let threshold = 2;
 let partiesNumber = 3;

 let keygenStats = null;
 let keygenTimes = {};

 let signNum = 1;
 let signHashFn = "SHA256";
 let signMessage = "Something to sign";
 let generatingSign = false;

 let signStats = null;
 let signTimes = {};

 let selectedPk = null;

 let selectPk = false;

 $: validPartiesNum =
        +partiesNumber && partiesNumber >= 2 && partiesNumber <= 3;
 $: validThreshold =
        +threshold && threshold > 1 && threshold <= partiesNumber;

 const handleGenKeys = async () => {
     let startTime = Date.now();

     generatingKeys = true;

     let loadedConfig = await clusterConfig();

     try {
         let { setup, instance } = await createKeygenSetup(loadedConfig, partiesNumber, threshold);

         let setupGen = Date.now();

         console.log('DKG setup gen', setupGen - startTime);

         let abort = new AbortController();

         let ws = await msg_relay_connect(wsUrl(loadedConfig.setup.relay), abort.signal);

         let relayConnTime = Date.now();

         ws.send(setup);
         ws.close();

         let genStart = Date.now();

         let resp = await Promise.all(
             loadedConfig
                 .nodes
                 .slice(0, partiesNumber)
                 .map((n) => startDkg(n.endpoint, instance))
         );

         let genEnd = Date.now();

         keygenStats = resp;
         keygenTimes = {
             totalTime: genEnd - startTime,
             setupGenTime: setupGen - startTime,
             relayConnTime: relayConnTime - setupGen
         };

         console.log('conn time', relayConnTime - setupGen);

         console.log('resp[0]', resp[0]);

         cloudPublicKeys.update((keys) => {
             return {...keys, [resp[0].public_key]: { n: partiesNumber, t: threshold }}
         });

         if (selectedPk === null) {
             selectedPk = resp[0].public_key;
         }

     } finally {
         generatingKeys = false;
     }
 };

 const handleSignGen = async () => {
     let startTime = Date.now();

     generatingSign = true;

     let loadedConfig = await clusterConfig();

     let keyInfo = $cloudPublicKeys[selectedPk];

     console.log('sign keyinfo', keyInfo);

     try {
         let { setup, instance } = await createSignSetup(
             loadedConfig,
             decodeBase64(selectedPk),
             new TextEncoder().encode(signMessage),
             threshold
         );

         let setupGen = Date.now();

         let abort = new AbortController();

         let ws = await msg_relay_connect(wsUrl(loadedConfig.setup.relay), abort.signal);

         let relayConnTime = Date.now();

         ws.send(setup);

         let genStart = Date.now();

         let resp = await Promise.all(
             loadedConfig
                 .nodes
                 .slice(0, threshold).map((n) => startDsg(n.endpoint, instance))
         );

         let genEnd = Date.now();

         signStats = resp;
         signTimes = {
             totalTime: genEnd - startTime,
             relayConnTime: genStart - startTime
         };

         console.log('resp', resp);

     } finally {
         generatingSign = false;
     }
 };

 const doSelectPk = (pk) => {
     selectPk = false;
     selectedPk = pk;
     console.log('current pk', pk);
 };

 const pkInfo = (pk) => {
     let info = $cloudPublicKeys[pk];
     return `N: ${info.n}, T ${info.t}`;
 };

</script>

<details open>
    <summary>
        <strong>Key generation with "all cloud nodes" network</strong>
    </summary>

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

    <SummaryTimes {... keygenTimes} />
    <TimeMetrics stats={keygenStats} showLegend="true" />

</details>

{#if Object.keys($cloudPublicKeys).length == 0 }
    <p> Gnerate at leat one key </p>
{:else}
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

    <details role="list" bind:open={selectPk}>
        <summary aria-haspopup="listbox">{selectedPk} | {pkInfo(selectedPk)}</summary>
        <ul role="listbox">
            {#each Object.keys($cloudPublicKeys) as pk}
                <li>
                    <label for="pk">
                        <span role="button" tabindex="-1"  on:click={() => doSelectPk(pk)} on:keypress={() => null}>
                            <input type="radio" name="pk" value="{pk}" checked={pk == selectedPk}>
                            { pk }
                        </span>
                    </label>
                </li>
            {/each}
        </ul>
    </details>

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

    <SummaryTimes {... signTimes} />
    <TimeMetrics stats={signStats} />

</details>
{/if}
