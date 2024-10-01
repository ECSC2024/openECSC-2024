import flowbitePlugin from 'flowbite/plugin'

import type { Config } from 'tailwindcss';

export default {
	content: ['./src/**/*.{html,js,svelte,ts}', './node_modules/flowbite-svelte/**/*.{html,js,svelte,ts}'],
    darkMode: 'selector',
	theme: {
		extend: {
			colors: {
				// flowbite-svelte
				primary: {
					"50":"#eff6ff",
					"100":"#dbeafe",
					"200":"#bfdbfe",
					"300":"#93c5fd",
					"400":"#60a5fa",
					"500":"#3b82f6",
					"600":"#2563eb",
					"700":"#1d4ed8",
					"800":"#1e40af",
					"900":"#1e3a8a"
				}
			}
		}
	},

	plugins: [flowbitePlugin]
} as Config;