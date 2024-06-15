# OliCyber.IT 2024 - National Final

## [web] Guess the flag! (82 solves)

Just give it a try

Site: [http://guesstheflag.challs.external.open.ecsc2024.it](http://guesstheflag.challs.external.open.ecsc2024.it)

Author: Lorenzo Leonardini <@pianka>

## Overview

The challenge allows us to try and guess the flag. The check for the correct flag is performed client-side in the browser, but the check is obfuscated using JSFuck.

## Solution

In Chrome we can just open the console in the developer tools and type `submit.onclick`. This will print us the string representation of the onsubmit function, which is the evaluated JSFuck. Firefox doesn't do this, it just prints "function", but we can use one of the many online JSFuck decoding tools to retrieve the original source code.

The code is just something like

```js
if (flag.value === 'flag{....}') {
	win();
} else {
	loose();
}
```
