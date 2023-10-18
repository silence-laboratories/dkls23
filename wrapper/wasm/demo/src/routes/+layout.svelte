<script lang="ts">
 import '@picocss/pico'

 import { coreLoaded } from '$lib/dkls'

</script>


<header class="container">
    <hgroup>
        <h1> SL demo</h1>
        <p>
        </p>
    </hgroup>
</header>


<main class="container">
    {#if $coreLoaded }
        <slot />
    {:else}
        <p> loading ... </p>
    {/if}
</main>
