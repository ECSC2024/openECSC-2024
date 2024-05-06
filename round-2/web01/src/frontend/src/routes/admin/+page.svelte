<script lang="ts">
    import {onMount} from 'svelte';
    import {Button} from 'flowbite-svelte';
    import {PUBLIC_BACKEND_URI} from '$env/static/public';

    var flag: String | null = null;

    onMount(() => {
        let backendUri = PUBLIC_BACKEND_URI;
        fetch(
            `${backendUri}/api/v1/admin`,
            {
                headers: {
                    "Authorization": `Bearer ${sessionStorage.getItem("accessToken")}`,
                    "Host": `${backendUri}`
                }
            }
        ).then((response) => {
            response.json().then(
                (body) => {
                    console.log(body);
                    return;
                }
            )
        })
    })

    import {utils} from '$lib/utils';
</script>

<div class="text-center m-32">
    <Button
        size="xl"
        on:click={() => utils.generateReport(PUBLIC_BACKEND_URI)}>
        Generate report 
    </Button>
</div>