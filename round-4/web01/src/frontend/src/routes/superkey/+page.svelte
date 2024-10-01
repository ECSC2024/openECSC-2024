<script lang="ts">
    import { onMount } from "svelte";
    import { Spinner, Alert } from "flowbite-svelte";

    let loading = true;
    let allowed = false;

    let flag = "";

    onMount(() => fetch(
        "/api/v1/superkey",
        {
            credentials: "same-origin",
        }
    ).then((response) => {
        if (response.status === 200) {
            response.json().then((value) => {
                flag = value["msg"];
                allowed = true;
            })
        }
        loading = false;
    }));
</script>

{#if loading}
    <div class="spinner">
        <Spinner />
    </div>
{/if}

{#if !loading && !allowed}
    <div class="py-8">
        <Alert color="red">
            Hey, you're not the admin...
        </Alert>
    </div>
{/if}

{#if !loading && allowed}
    <div class="py-8">
        <Alert color="green">
            {flag}
        </Alert>
    </div>
{/if}