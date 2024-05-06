<script lang="ts">
	import '../app.pcss';
	import {
		NavLi,
		NavUl,
		Button,
		Navbar,
		NavBrand,
		NavHamburger,
	} from 'flowbite-svelte';

	import logo from '$lib/assets/logo.svg';
	import {utils} from '$lib/utils';
	import {onMount} from 'svelte';
	import {PUBLIC_BACKEND_URI} from '$env/static/public';

	var logged = false;
	var admin = false;
	onMount(() => {
    	logged = utils.loggedIn();
		admin = utils.isAdmin();
	});
</script>

<Navbar>
	<NavBrand href="/">
		<img
			src={logo}
			class="me-3 h-6 sm:h-9"
			alt="Laundry logo"
		/>
		<span class="self-center whitespace-nowrap text-xl font-semibold dark:text-white">
			Best laundry
		</span>
	</NavBrand>
		<div class="flex md:order-2">
			{#if !logged}
				<Button
					size="sm"
					on:click={() => utils.login(PUBLIC_BACKEND_URI)}
				>
					Login
				</Button>
			{/if}
			{#if logged}
				<Button
					size="sm"
					on:click={utils.logout}
				>
					Logout
				</Button>
			{/if}
			<NavHamburger/>
		</div>
	<NavUl class="order-1">
		<NavLi href="/" active={true}>Home</NavLi>
		<NavLi href="/laundry">Laundry</NavLi>
		<NavLi href="/amenities">Amenities</NavLi>
		{#if admin}
			<NavLi href="/admin">Admin</NavLi>
		{/if}
	</NavUl>
</Navbar>

<slot />