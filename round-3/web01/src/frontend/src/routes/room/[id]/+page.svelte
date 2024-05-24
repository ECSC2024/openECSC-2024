<script lang="ts">
  import cheapOne from '$lib/assets/0cWHPVtqYK1gq34IUieZAYxE.jpg';
  import regularOne from '$lib/assets/uiVYozzRgRXF0CyMkfdwCGrI.jpg';
  import luxuryOne from '$lib/assets/47aOlxCtCvBYKNrFdkwtHRsl.jpg';
  import royalRoom from '$lib/assets/IQXygEah2dI37aOqeBEVYfQ1.jpg';
  import type { PageServerData } from '../$types';

  const roomImages: object = {
    "0cWHPVtqYK1gq34IUieZAYxE": cheapOne,
    "uiVYozzRgRXF0CyMkfdwCGrI": regularOne,
    "47aOlxCtCvBYKNrFdkwtHRsl": luxuryOne,
    "IQXygEah2dI37aOqeBEVYfQ1": royalRoom
  };

  function book() {
    alert("Booking confirmed!");
    location.href = "/";
  }

  export let data: PageServerData;

</script>

<img src={roomImages[data.roomId]}>
<button-container id="button-container">
  <button on:click={book} class="bg-transparent hover:bg-blue-500 text-blue-700 font-semibold hover:text-white py-2 px-4 border border-blue-500 hover:border-transparent rounded">
    Book
  </button>
</button-container>

<footer>Icons by <a href="www.icons8.com">icons8</a></footer>
<style>
  footer {
    position: fixed;
    bottom: 0;
    font-size: .4em;
  }

  img {
    height: 35em;
    margin: auto;
    padding: 2em;
    border-radius: 10%;
  }

  #button-container {
    display: flex;
    flex-direction: row;
    align-items: center;
    width: 100vw;
    justify-content: center;
  }
</style>
