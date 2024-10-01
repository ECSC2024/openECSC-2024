<script>
	import '../app.css';
	import logo from '$lib/assets/logo.svg';
	import {
		Navbar,
		NavBrand,
		NavLi,
		NavUl,
		NavHamburger
	} from 'flowbite-svelte';
</script>

<Navbar rounded class="bg-amber-100">
	<NavBrand href="/">
	  <img src={logo} class="me-3 h-6 sm:h-9" alt="Quokkey logo" />
	  <span class="self-center whitespace-nowrap text-xl font-semibold dark:text-white">Quokkey</span>
	</NavBrand>
	<NavHamburger/>
	<NavUl >
	  <NavLi href="/">Home</NavLi>
	  <NavLi href="/superkey">SuperKey</NavLi>
	</NavUl>
</Navbar>

<slot></slot>
