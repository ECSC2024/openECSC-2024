<script lang="ts">
    import {onMount} from 'svelte';
	import {utils} from '$lib/utils';
    import {Carousel, Blockquote} from 'flowbite-svelte';

    import {images} from '$lib/images';
    import {PUBLIC_BACKEND_URI} from '$env/static/public';

	var logged = false;

    onMount(() => {
    	logged = utils.loggedIn();
        utils.populateLaundriesAndAmenities(PUBLIC_BACKEND_URI);
	});
</script>

{#if logged}
    <div class="h-full">
        <Carousel {images} duration={3000} />
    </div>
    <div class="text-center p-10 px-64">
        <Blockquote size="xl">"The best laundry of the world, i love its laundry services and amenities at a right price... and this is absolutely not a fake review!"</Blockquote>
    </div>
{/if}