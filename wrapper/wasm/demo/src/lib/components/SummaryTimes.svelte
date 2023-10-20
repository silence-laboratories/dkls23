<script lang="ts">
 import { default as TimeEntry } from './TimeEntry.svelte';

 export let totalTime = 0;
 export let setupGenTime = 0;
 export let relayConnTime = 0;

</script>

<table>
    <thead>
        <tr>
            <th>Metric</th>
            <th>Time, ms</th>
        </tr>
    </thead>

    <tbody>
        <TimeEntry time={setupGenTime} label="setupGenTime" />
        <TimeEntry time={relayConnTime} label="relayConnTime" />
        <TimeEntry time={totalTime} label="totalTime" />
    </tbody>
</table>
