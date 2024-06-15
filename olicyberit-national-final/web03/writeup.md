# OliCyber.IT 2024 - National Final

## [web] AffiliatedStore (6 solves)

We've been working on this new web store with a complex affiliation program. We are still working on it, and the payment part is not complete yet. In the meantime, can you help us pentest this part?

Site: [http://affiliatedstore.challs.external.open.ecsc2024.it](http://affiliatedstore.challs.external.open.ecsc2024.it)

Author: Lorenzo Leonardini <@pianka>

## Overview

The challenge presents a web store. During registration we can specify an affiliation id. If someone makes a purchase after registering with our id, we can see the order details in our dashboard.

There is a feedback functionality that allows to share our cart with an admin. The cart status is memorized in the URL params. When we submit a cart for feedback, the admin types the flag in the order message and makes the purchase.

## Solution

Our objective is to read the flag typed in the order custom message. If you register with an affiliation id, all your custom messages are available to the user you got the affiliation id from. So we want the admin to have our affiliation.

Weirdly enough, the affiliation id is stored in `sessionStorage`.

The vulnerability resides in the cart page, where the following code is vulnerable to prototype pollution:

```js
const cart = JSON.parse(atob(new URL(location.href).searchParams.get('cart')));

const products = {};

cart.forEach((el) => {
	const product = products[el.id] || (products[el.id] = {});

	for (const [key, value] of Object.entries(el)) {
		if (key === 'id') continue;
		product[key] = DOMPurify.sanitize(value);
	}
});
```

if we add to the cart an item with the following format:

```json
{
	"id": "__proto__",
	"affiliation": "[our id]"
}
```

we can use the prototype pollution to read a custom value from sessionStorage:

```js
fetch('/api/order', {
	method: 'POST',
	headers: {
		'Content-Type': 'application/json'
	},
	body: JSON.stringify({
		cart: cart,
		message: customMessage.value,
		affiliation: sessionStorage.affiliation
	})
});
```
