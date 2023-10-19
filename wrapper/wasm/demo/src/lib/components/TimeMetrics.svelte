<script lang="ts">
 export let stats = undefined;
 export let showLegend = false;
</script>

{#if stats}
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
            {#each stats as n, idx}
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

    {#if showLegend }
        <p>
            A few notes. <b> Total time </b> is a time from receiving an
            initial message from browser to finishing calculation of a key
            share. <b>Wait time</b> is how much time a node spent waiting
            for a message from other nodes out of <b>Total time</b>. The
            diffence of two is an estimation of CPU time.
        </p>
    {/if}
{/if}
