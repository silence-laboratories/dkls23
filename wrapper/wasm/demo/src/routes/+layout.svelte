<script lang="ts">
 import '@picocss/pico'

 import { coreLoaded } from '$lib/dkls'

</script>

<header class="container">
    <nav>
        <ul>
            <li><strong>SL Demo</strong></li>
        </ul>

        <ul>
            <li><a href="/">Intro</a></li>
            <li><a href="/all-cloud">All cloud</a></li>
            <li><a href="/web-cloud">Web &amp cloud</a></li>
            <li><a href="/web-init">Web init</a></li>
            <li><a href="/web-join">Web join</a></li>
        </ul>
    </nav>
</header>

<main class="container">
    {#if $coreLoaded }
        <slot />
    {:else}
        <p> loading ... </p>
    {/if}
</main>
