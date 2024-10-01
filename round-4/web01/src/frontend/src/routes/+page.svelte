<script lang="ts">
    import { onMount } from "svelte";
    import { Card, Spinner } from "flowbite-svelte";
    import Login from "$lib/components/Login.svelte";

    let loading = true;
    let logged = false;
    let posts: {
        "id": "string",
        "title": "string",
        "text": "string",
    }[] = []
    onMount(() => fetch(
        "/api/v1/posts",
        {
            credentials: "same-origin",
        }
    ).then((response) => {
        if (response.status === 200) {
            logged = true;
            response.json().then((value) => posts = value)
        }
        loading = false;
    }));
</script>

{#if loading}
<div class="spinner">
    <Spinner />
</div>
{/if}

{#if !loading && !logged}
    <div class="py-8">
        <Login></Login>
    </div>
{/if}

{#if !loading && logged}
<div class="py-8 grid gap-y-2 grid-cols-2">
    {#each posts as p}
        <div>
            <Card>
                <h5 class="mb-2 text-2xl font-bold tracking-tight text-gray-900 dark:text-white">{p.title}</h5>
                <p class="font-normal text-gray-700 dark:text-gray-400 leading-tight">{p.text}</p>
                <p class="text-xs font-normal text-gray-700 dark:text-gray-400 leading-tight">(id: {p.id})</p>
            </Card>
        </div>
    {/each}
</div>
{/if}
