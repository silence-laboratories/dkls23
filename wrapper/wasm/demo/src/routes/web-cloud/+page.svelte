<script lang="ts">
 import { default as TimeMetrics }      from '$lib/components/TimeMetrics.svelte';
 import { default as SummaryTimes }     from '$lib/components/SummaryTimes.svelte';
 import { configs, wsUrl }              from '$lib/config';
 import { decodeBase64, encodeBase64 }  from '$lib/base64';
 import { encodeHex }                   from '$lib/hex';
 import { keyshares }                   from '$lib/stores';

 import {
     createKeygenSetupOpts,
     createSignSetup,
     startDkg,
     startDsg
 } from '$lib/nodes';

 import {
     init_dkg,
     join_dsg,
     genInstanceId,
     verifyingKey,
     msg_relay_connect,
     createAbortMessage
 } from 'dkls-wasm';

 let generatingKeys = false;
 let threshold = 2;
 let partiesNumber = 3;

 let keygenWebStats = null;
 let keygenWebTimes = {};

 let signNum = 1;
 let signHashFn = "SHA256";
 let signMessage = "Something to sign";
 let generatingSign = false;

 let signStats = null;
 let signTimes = {};

 $: validPartiesNum =
        +partiesNumber && partiesNumber > 2 && partiesNumber <= 5;
 $: validThreshold =
        +threshold && threshold > 1 && threshold < partiesNumber;

 let selectShare = false;
 let selectedShare = $keyshares[0] || null;

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

         let [share, ...clouds] = await Promise.all([
             web_party,
             ...cluster.nodes.slice(1).map((n) => startDkg(n.endpoint, opts.instance))
         ]);

         let genEnd = Date.now();

         console.log('pk', share.publicKey(), encodeBase64(share.publicKey()));

         keyshares.update((shares) => [...shares, share]);

         keygenWebStats = clouds;

         keygenWebTimes = {
             totalTime: genEnd - startTime,
             setupGenTime: setupGen - startTime,
         };
     } finally {
         generatingKeys = false;
     }
 };

 const handleSignGen = async () => {
 };

</script>

<details open>
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
    <TimeMetrics stats={keygenWebStats && keygenWebStats} />

</details>

{#if $keyshares.length == 0}
    <p> Generate a least one key </p>
{:else}
<details>
    <summary><strong>Signature generation</strong></summary>

    <p>
        Prepare a signature description message, publish it via the
        message relay service, start execution of DSG on this machine
        and tigger DKG on cloud nodes.
    </p>

    <details role="list" bind:open={selectShare}>
        <summary aria-haspopup="listbox">{selectedShare.publicKey()}</summary>
        <ul role="listbox">
            {#each $keyshares as share}
                <li>
                    <label for="pk">
                        <a href="#" on:click={() => doSelectShare(share)} >
                            <input type="radio" name="pk" value="{pk}" checked={pk == selectedPk}>
                            { pk }
                        </a>
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
