# OliCyber.IT 2024 - National Final

## [web] !phishing (15 solves)

I created this amazing website that doesn't do absolutely anything (unless you're an admin :P).
It only accepts registering with a `@fakemail.olicyber.it`, luckily you can request one as well!

Note: the administrator followed a training against phishing, so it will only click on links coming from the official platform email!

Note: don't waste time on the fakemail service, it was only created for fake emails, it is not the center of the challenge.

Challenge: [http://not-phishing.challs.external.open.ecsc2024.it:38100](http://not-phishing.challs.external.open.ecsc2024.it:38100)

Fakemail: [http://not-phishing-fakemail.challs.external.open.ecsc2024.it:38101](http://not-phishing-fakemail.challs.external.open.ecsc2024.it:38101)

Author: Aleandro Prudenzano <@drw0if>

## Overview
The challenge appears as a website that offers no apparent functionalities but allows:
- Registration
- Login
- Email verification
- Passwordless login if you have access to the associated user's email
- Access to an admin portal that provides the flag if you have the necessary privileges

The crucial aspects concern the use of email for account verification and passwordless login.

Emails sent are not real but can be viewed using the provided `fakemail` portal. Users can register on this portal, log in, and check their inbox.

This portal only allows receiving and deleting emails, not sending them.

## Vulnerability
The service has a misconfigured nginx, making it vulnerable to `Host` header spoofing. The only configured virtual host (through the `server` block) is the service itself.

Being the first and only configured server, it is used as the default to serve any request arriving at the nginx port, without performing any checks on the `Host` header value.

To construct emails, the application uses the content of the `Host` header:
```php
$domain_name = $_SERVER['HTTP_HOST'];
send_mail(
    $email,
    "Login",
    "Go to http://$domain_name/token_login.php?token=$token to log in!"
);
```
## Solution
Since we can freely modify the content of the Host header and it is used to construct the domain of the login link, we can request the admin account login by specifying, as host, a service controlled by us.
This way, when the admin visits the link in the official site email (which they trust), we can capture the login token.

Once a session as admin is obtained, just go to the `/admin.php` page to get the flag.
