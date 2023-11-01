<script lang="ts">
 import { goto } from '$app/navigation'
</script>

<section>
    <h6>Introduction</h6>

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

    <!-- <p>
         The following sections will guide you through several
         examples. You could execute them and get some time metrics.
         </p> -->

    <p>
        The typical scheme of all protocols: prepare a "setup message"
        and publish it for all participants via the message relay
        service and then trigger execution of a protocol by making a
        special request to all network nodes.
    </p>
</section>
