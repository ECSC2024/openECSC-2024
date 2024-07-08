<script lang="ts">
	import rococavern from "$lib/assets/01a86fde-cb26-450d-a0e8-41fbb1ad349f.jpg";
	import woodHouse from "$lib/assets/72d5be17-c7cc-4dd4-872f-57e587f3bd30.jpg";
	import hobbitHouse from "$lib/assets/27b7e779-f24e-4655-9d29-e46c89f55d55.jpg";
	import wizardTower from "$lib/assets/d614199b-22c2-4b40-bec8-39f0d7b2e922.jpg";
	import valinorDream from "$lib/assets/ac1b9717-0be8-4ef5-b7f4-71aa264f683a.jpg";
	import rivendellPearl from "$lib/assets/84d34112-e68d-4266-bb7c-ef8ba87d09e1.jpg";

	let images: {[key: string]: string} = {
		"01a86fde-cb26-450d-a0e8-41fbb1ad349f": rococavern,
		"72d5be17-c7cc-4dd4-872f-57e587f3bd30": woodHouse,
		"27b7e779-f24e-4655-9d29-e46c89f55d55": hobbitHouse,
		"d614199b-22c2-4b40-bec8-39f0d7b2e922": wizardTower,
		"ac1b9717-0be8-4ef5-b7f4-71aa264f683a": valinorDream,
		"84d34112-e68d-4266-bb7c-ef8ba87d09e1": rivendellPearl,
	};

	import mirian from "$lib/assets/mirian.png";
	import logo from '$lib/assets/logo.svg';

	import '../app.css';
	import {
		ListgroupItem,
		Listgroup,
		Spinner,
		Search,
		Button,
		Toast,
		Label,
		Input,
		Modal,
		Img,
	} from 'flowbite-svelte';
  	import {
		CloseCircleSolid,
		CheckCircleSolid,
		SearchOutline,
		BellOutline,
	} from 'flowbite-svelte-icons';

	import properties from '$lib/properties';
	let filtered_properties = properties;
	let search_value = '';
	function filter() {
		filtered_properties = properties.filter((el) => {
			console.log(el.name.toUpperCase().includes(search_value.toUpperCase()))
			return el.name.toUpperCase().includes(search_value.toUpperCase()) ||
			el.description.toUpperCase().includes(search_value.toUpperCase()) ||
			el.seller.toUpperCase().includes(search_value.toUpperCase());
		})
	}

	import { blur } from 'svelte/transition';
	import CryptoJS from 'crypto-js';
	let toast_list: [string, string][] = [];
	let notify_modal: boolean = false;
	let calculating_pow: boolean = false;
	let proposal_uuid = "";
	function send_notification() {
		fetch("/api/v1/pow").then((response) => {
			response.json().then((decoded) => {
				let sol = "0";
				calculating_pow = true;
				while (CryptoJS.SHA256(sol).toString(CryptoJS.enc.Hex).substring(59) != decoded.pow) {
					sol = (parseInt(sol) + 1).toString()
				}
				calculating_pow = false;
				fetch(
					"/api/v1/notify",
					{
						"method": "POST",
						"headers": {"Content-Type": "application/json"},
						"body": JSON.stringify({
							"proposal_uuid": proposal_uuid,
							"pow_uuid": decoded.uuid,
							"pow_solution": sol,
						}),
					}
				).then((response) => {
					if (response.status !== 200) {
						toast_list = toast_list.concat([["KO", "Notification failed"]]);
					} else {
						toast_list = toast_list.concat([["OK", "Notification succeded"]]);
					}
				})
			})
		})

		notify_modal = false;
	}
</script>

{#if calculating_pow}
	<div class="w-screen h-screen bg-[#0000008f]">
		<Spinner />
	</div>
{/if}

{#each toast_list as toast}
	<Toast transition={ blur } position="top-right" params={{ amount: 2000 }} color={toast[0] === "OK" ? "green" : "red"}>
		<svelte:fragment slot="icon">
			{#if toast[0] === "OK"}
				<CheckCircleSolid class="w-5 h-5" />
				<span class="sr-only">Check icon</span>
			{/if}
			{#if toast[0] === "KO"}
				<CloseCircleSolid class="w-5 h-5" />
				<span class="sr-only">Exclamation icon</span>
			{/if}
		</svelte:fragment>
		{toast[1]}
	</Toast>
{/each}

<Img src={logo} alt="logo" alignment="mx-auto" size="max-w-xs" />

<h1 class="font-bold text-4xl mb-16 text-center">Smaug real estate</h1>

<div class="flex gap-2 ml-32 mr-32">
	<Search size="md" bind:value={search_value} />
	<Button class="!p-2.5" on:click={filter}>
		<SearchOutline class="w-6 h-6" />
	</Button>
	<Button class="!p-2.5" on:click={() => {notify_modal=true}}>
		<BellOutline class="w-6 h-6" />
	</Button>
</div>

<Listgroup class="ml-32 mr-32 border-0 dark:!bg-transparent">
	{#each filtered_properties as property}
    <ListgroupItem>
		<div class="flex items-center space-x-4 rtl:space-x-reverse mt-8 mb-8">
			<Img src={images[property.id]} size="max-w-xs"/>
			<div class="flex-1 min-w-0">
				<h1 class="ml-12 text-3xl text-bold text-gray-900 truncate dark:text-white">
					{property.name}
				</h1>
				<p class="ml-12 text-sm text-gray-500 dark:text-gray-400">
					{property.description}
				</p>
				<p class="ml-12 mt-12 text-semibold italic">
					SELLER: {property.seller}
				</p>
			</div>
			<div class="flex flex-row items-center text-base font-semibold text-gray-900 dark:text-white">
				<div class="ml-12">{property.price}</div>
				<img src={mirian} alt="mirian" class="w-4 ml-3 rounded-full">
			</div>
		</div>
	</ListgroupItem>
	{/each}
</Listgroup>

<Modal title="Notify our agents" bind:open={notify_modal} autoclose>
	<p class="text-base leading-relaxed text-gray-500 dark:text-gray-400">Notify our agent about any inserted sell proposal by inserting here the related uuid</p>
	<div>
		<Label for="proposal-uuid" class="mb-2">Proposal uuid</Label>
		<Input type="text" id="proposal-uuid" placeholder="00000000-0000-0000-0000-000000000000" pattern={"/^[0-9A-F]{8}-[0-9A-F]{4}-[4][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i"} bind:value={proposal_uuid} required />
		<Button class="mt-6" on:click={send_notification}>
			Submit
		</Button>
	</div>
</Modal>