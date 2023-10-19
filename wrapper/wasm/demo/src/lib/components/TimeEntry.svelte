<script lang="ts">
 export let time = 0;
 export let label = "";
</script>

{#if time }
    <tr>
        <td><b>{label}</b></td>
        <td>{time}</td>
    </tr>
{/if}
