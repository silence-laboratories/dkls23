<script lang="ts">
 import '@picocss/pico'

 import { coreLoaded } from '$lib/dkls'

</script>

<header class="container">
    <hgroup>
        <nav>
            <ul>
                <li><img src="/sl-logo.svg" class="logo" alt="SL Logo" /></li>
                <li><strong>DKLs23 Demo</strong></li>
            </ul>

            <ul>
                <li><a href="/">Intro</a></li>
                <li><a href="/all-cloud">All cloud</a></li>
                <li><a href="/web-cloud">Web &amp cloud</a></li>
            </ul>
        </nav>
    </hgroup>
</header>

<main class="container">
    {#if $coreLoaded }
        <slot />
    {:else}
        <p> loading ... </p>
    {/if}
</main>

<style>
    .logo {
        width: 150px; /* Logo takes the full width on smaller screens */
        margin-top: 5%; /* Add some space between the logo and the text */
    }
</style>
