
<script lang="ts">
  import cheapOne from '$lib/assets/0cWHPVtqYK1gq34IUieZAYxE.jpg';
  import regularOne from '$lib/assets/uiVYozzRgRXF0CyMkfdwCGrI.jpg';
  import luxuryOne from '$lib/assets/47aOlxCtCvBYKNrFdkwtHRsl.jpg';
  import royalRoom from '$lib/assets/IQXygEah2dI37aOqeBEVYfQ1.jpg';
  import type { PageServerData } from './$types';

  const roomImages: object = {
    "0cWHPVtqYK1gq34IUieZAYxE": cheapOne,
    "uiVYozzRgRXF0CyMkfdwCGrI": regularOne,
    "47aOlxCtCvBYKNrFdkwtHRsl": luxuryOne,
    "IQXygEah2dI37aOqeBEVYfQ1": royalRoom
  };

  export let data: PageServerData;
</script>

<div id="default-carousel" class="relative w-full" data-carousel="slide">
  <div class="relative h-56 overflow-hidden md:h-96">
    {#each data.rooms as room}
    <div class="hidden duration-700 ease-in-out" data-carousel-item>
      <img src={roomImages[room.id]} class="absolute block w-full -translate-x-1/2 -translate-y-1/2 top-1/2 left-1/2" alt="...">
    </div>
    {/each}
  </div>
  <div class="absolute z-30 flex -translate-x-1/2 bottom-5 left-1/2 space-x-3 rtl:space-x-reverse">
    {#each data.rooms as _}
    <button type="button" class="w-3 h-3 rounded-full" aria-current="true" aria-label="Slide 1" data-carousel-slide-to="0"></button>
    {/each}
  </div>
  <button type="button" class="absolute top-0 start-0 z-30 flex items-center justify-center h-full px-4 cursor-pointer group focus:outline-none" data-carousel-prev>
    <span class="inline-flex items-center justify-center w-10 h-10 rounded-full bg-white/30 dark:bg-gray-800/30 group-hover:bg-white/50 dark:group-hover:bg-gray-800/60 group-focus:ring-4 group-focus:ring-white dark:group-focus:ring-gray-800/70 group-focus:outline-none">
      <svg class="w-4 h-4 text-white dark:text-gray-800 rtl:rotate-180" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 6 10">
        <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 1 1 5l4 4"/>
      </svg>
      <span class="sr-only">Previous</span>
    </span>
  </button>
  <button type="button" class="absolute top-0 end-0 z-30 flex items-center justify-center h-full px-4 cursor-pointer group focus:outline-none" data-carousel-next>
    <span class="inline-flex items-center justify-center w-10 h-10 rounded-full bg-white/30 dark:bg-gray-800/30 group-hover:bg-white/50 dark:group-hover:bg-gray-800/60 group-focus:ring-4 group-focus:ring-white dark:group-focus:ring-gray-800/70 group-focus:outline-none">
      <svg class="w-4 h-4 text-white dark:text-gray-800 rtl:rotate-180" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 6 10">
        <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m1 9 4-4-4-4"/>
      </svg>
      <span class="sr-only">Next</span>
    </span>
  </button>
</div>

<div id="card-container">
  {#each data.rooms as room}
  <a href="/room/{room.id}" class="block max-w-sm p-6 bg-white border border-gray-200 rounded-lg shadow hover:bg-gray-100 dark:bg-gray-800 dark:border-gray-700 dark:hover:bg-gray-700">
    <h5 class="mb-2 text-2xl font-bold tracking-tight text-gray-900 dark:text-white">
      {room.Name}
    </h5>
    <p class="font-normal text-gray-700 dark:text-gray-400">
      {room.description}
    </p>
  </a>
  {/each}
</div>

<footer>Icons by <a href="www.icons8.com">icons8</a></footer>
<style>
  #card-container {
    display: flex;
    flex-direction: row;
    margin: 10px;
    gap: 20px;
    align-items: center;
    justify-content: center;
  }

  footer {
    position: fixed;
    bottom: 0;
    font-size: .4em;
  }
</style>
