<script lang="ts">
    import slurmlogo from '$lib/assets/slurmlogo.png';
    import slurmmckenzie from '$lib/assets/slurmmckenzie.png';

    import {
        Img,
        Spinner,
        Listgroup,
        Blockquote,
        ListgroupItem,
    } from 'flowbite-svelte';

    import { onMount } from 'svelte';

    let files: {
        "author": string,
        "filename": string,
        "description": string,
        "id": string,
    }[] = [];
    onMount(() => {
        fetch("/api/v1/files").then((response) => {
            response.json().then((body) => {
                files = body;
            });
        });
    });

    import { MD5 } from 'crypto-js';

    let uploaded: any = null;

    onMount(() => document.getElementById('fileInput')?.addEventListener('change', (e) => {
        let file: File = e.target?.files[0];
        let filename: string = file.name;
        let description: string = `${file.lastModified} | ${file.size}`;
        let author: string = 'challenger'
        file.text().then((content) => fetch(
            '/api/v1/files',
            {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    filename: filename,
                    description: description,
                    author: author,
                    content: content,
                }),
            }
        ).then((response) => {
            if (response.status >= 400) {
                alert("Invalid file! Only letters accepted, max length is 200 bytes");
            }
            else {
                alert("Thank you for your suggestion")
            }
        }));
    }, false));
</script>

<div class="flex flex-col justify-center items-center">
    <Img src={slurmlogo} alt="Slurm logo" size="h-52 m-5"/>
    <Blockquote size="xl">"The best drink humanoid snails ever made!" - Smith Truereview</Blockquote>
</div>

<div class="flex flex-col justify-center items-center">
    {#if files}
        <Listgroup active class="w-96 m-10">
            <h3 class="p-1 text-center text-xl font-medium text-gray-900 dark:text-white">Marketing materials</h3>
            {#each files as file}
                <ListgroupItem on:click={() =>
                        fetch(`/api/v1/files/${file.id}`).then((response) => {
                            if (response.status >= 400) {
                                alert("ERROR: You can't download this");
                                return;
                            }
                            response.text().then((text) => {
                                let checksum = MD5(text).toString();
                                fetch(`/api/v1/files/${file.id}/checksum`).then((response) => {
                                    response.json().then((body) => {
                                        if (body.checksum != checksum) {
                                            alert(`Corrupted file: ${file.filename}`);
                                        }
                                        else {
                                            alert(`CONTENT: ${text}`);
                                        }
                                    })
                                })
                            });
                        })
                    }>
                        {file.description}
                </ListgroupItem>
            {/each}
        </Listgroup>
    {/if}
    {#if !files}
        <Spinner />
    {/if}
</div>

<div class="flex flex-col justify-center items-center">
    <Img src={slurmmckenzie} alt="Slurm Mckenzie" size="h-52 m-5"/>
    <p>Upload a marketing suggestion</p>
    <input bind:files={uploaded} id="fileInput" type="file" class="m-10" />
</div>