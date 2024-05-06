<script lang="ts">
    import smallOne from '$lib/assets/ad80d726-f160-44e0-b715-4836f53043b0.jpg';
    import mediumOne from '$lib/assets/413758ab-15ff-4e27-9190-cd8cdf27e173.jpg';
    import largeOne from '$lib/assets/65f97b5c-fc87-47e1-bd57-8c7d1de1803a.jpg';
    import gargantuanOne from '$lib/assets/f5138c9e-d2da-41f1-a925-281931ffb021.jpg';
    import vendingMachine from '$lib/assets/a90850b3-ecae-454e-a175-938796c4e808.jpg';
    import tableFootball from '$lib/assets/1517a644-80ad-449e-bed7-9480f2c7b0e3.jpg';

    const images: object = {
        "ad80d726-f160-44e0-b715-4836f53043b0": smallOne,
        "413758ab-15ff-4e27-9190-cd8cdf27e173": mediumOne,
        "65f97b5c-fc87-47e1-bd57-8c7d1de1803a": largeOne,
        "f5138c9e-d2da-41f1-a925-281931ffb021": gargantuanOne,
        "a90850b3-ecae-454e-a175-938796c4e808": vendingMachine,
        "1517a644-80ad-449e-bed7-9480f2c7b0e3": tableFootball,
    };

    import {onMount} from 'svelte';
    import {utils} from '$lib/utils';
    import {Card} from 'flowbite-svelte';
    import {PUBLIC_BACKEND_URI} from '$env/static/public';

    var logged = false;
    let laundries: object[] = [];
    let amenities: object[] = [];

    onMount(() => {
        logged = utils.loggedIn();
        utils.populateLaundriesAndAmenities(PUBLIC_BACKEND_URI);
        if (!logged) {
            document.location = "/";
        }
        setInterval(() => {
            if (laundries.length == 0 || amenities.length == 0) {
                laundries = JSON.parse(sessionStorage.getItem("laundries") ?? "[]");
                amenities = JSON.parse(sessionStorage.getItem("amenities") ?? "[]");
            }
        }, 1000);
    });
</script>

<div class="flex gap-10 m-10">
    {#each amenities as amenity}
        <Card>
            <h5 class="mb-2 text-2xl font-bold tracking-tight text-gray-900 dark:text-white">
                {amenity.name}
            </h5>
            <img src={images[amenity.id]} alt="...">
            <p class="font-normal text-gray-700 dark:text-gray-400 leading-tight">
                {amenity.description}
            </p>
            <p>
                PRICE: {amenity.price}
            </p>
        </Card>  
    {/each}
</div>