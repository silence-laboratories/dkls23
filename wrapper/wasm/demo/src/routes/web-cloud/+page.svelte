<script lang="ts">
 import { default as TimeMetrics }      from '$lib/components/TimeMetrics.svelte';
 import { default as SummaryTimes }     from '$lib/components/SummaryTimes.svelte';
 import { clusterConfig, wsUrl }        from '$lib/config';
 import { decodeBase64, encodeBase64 }  from '$lib/base64';
 import { encodeHex }                   from '$lib/hex';
 import { keyshares }                   from '$lib/stores';

 import {
     createKeygenSetupOpts,
     createSignSetupOpts,
     startDkg,
     startDsg,
     randomSeed,
 } from '$lib/nodes';

 import {
     init_dkg,
     init_dsg,
     genInstanceId,
     verifyingKey,
     msg_relay_connect,
     createAbortMessage,
     type Keyshare
 } from 'dkls-wasm';

 let generatingKeys = false;
 let threshold = 2;
 let partiesNumber = 3;

 let keygenWebStats: any | null = null;
 let keygenWebTimes = {};

 let signNum = 1;
 let signHashFn = "SHA256";
 let signMessage = "Something to sign";
 let generatingSign = false;

 let signStats: any | null = null;
 let signTimes = {};

 $: validPartiesNum =
        +partiesNumber && partiesNumber >= 2 && partiesNumber <= 3;
 $: validThreshold =
        +threshold && threshold > 1 && threshold <= partiesNumber;

 let selectShare = false;
 let selectedShare: Keyshare | null = null;

 const handleGenKeysWeb = async () => {
     let startTime = Date.now();

     generatingKeys = true;

     let loadedConfig = await clusterConfig();

     try {
         let opts = await createKeygenSetupOpts(loadedConfig, partiesNumber, threshold);

         let setupGen = Date.now();

         console.log('DKG setup gen', setupGen - startTime);

         let msgRelayUrl = wsUrl(loadedConfig.setup.relay);

         let genStart = Date.now();

         let web_party = init_dkg(
             opts,
             encodeHex(loadedConfig.nodes[0].secretKey),
             msgRelayUrl,
             encodeHex(genInstanceId()) // seed
         );

         let [share, ...clouds] = await Promise.all([
             web_party,
             ...loadedConfig.nodes.slice(1, partiesNumber).map((n) => startDkg(n.endpoint, opts.instance))
         ]);

         let genEnd = Date.now();

         console.log('pk', share.publicKey(), encodeBase64(share.publicKey()));

         keyshares.update((shares) => [...shares, share]);

         if (selectedShare === null) {
             selectedShare = share;
         }

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
     if (selectedShare === null) {
         return;
     }

     let startTime = Date.now();

     generatingSign = true;

     let loadedConfig = await clusterConfig();

     let selectedPk = selectedShare.publicKey();

     try {
         let genStart = Date.now();
         let opts = await createSignSetupOpts(
             loadedConfig,
             selectedPk,
             new TextEncoder().encode(signMessage),
             threshold
         );

         let msgRelayUrl = wsUrl(loadedConfig.setup.relay);

         let setupGen = Date.now();

         let web_party = init_dsg(
             opts,
             encodeHex(loadedConfig.nodes[0].secretKey),
             msgRelayUrl,
             encodeHex(randomSeed()),
             selectedShare
         );

         let resp = await Promise.all(
             loadedConfig
                 .nodes
                 .slice(1, threshold).map((n) => startDsg(n.endpoint, opts.instance))
         );

         signStats = resp;

         let genEnd = Date.now();

         signTimes = {
             totalTime: genEnd - startTime,
             setupGenTime: setupGen - startTime,
         };

     } finally {
         generatingSign = false;
     };
 };

 const doSelectShare = (share: Keyshare) => {
     selectShare = false;
     selectedShare = share;
     console.log('current share', share);
 };

 const isSelectedShare = (share: Keyshare) => {
     return share === selectedShare;
 }

 const sharePk = (share: Keyshare | null) => share ? encodeHex(share.publicKey()) : "";


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
        <summary aria-haspopup="listbox">{sharePk(selectedShare)}</summary>
        <ul role="listbox">
            {#each $keyshares as share}
                <li>
                    <label for="pk">
                        <span role="button" tabindex="-1" on:click={() => doSelectShare(share)} on:keypress={() => null}>
                            <input type="radio" name="pk" value="{sharePk(share)}" checked={isSelectedShare(share)}>
                            { sharePk(share) }
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
