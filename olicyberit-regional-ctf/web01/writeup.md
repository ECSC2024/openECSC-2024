# OliCyber.IT 2024 - Regional CTF

## [web] Pretty please (142 solves)

Sometimes you should just ask :)

Website: [http://prettyplease.challs.external.open.ecsc2024.it](http://prettyplease.challs.external.open.ecsc2024.it)

Author: Stefano Alberto <@Xato>

## Overview

The challenge is a simple web page that lets you ask for the flag with a multiple choice form.

By reading the source code (directly available with a link in the page itself) you can see how the form is handled by the server.

```php
if (isset($_POST['how'])) {

    switch ($_POST['how']) {
        case 'now':
            echo '<div class="alert alert-danger">Please, learn some good manners</div>';
            break;
        case 'please':
            echo '<div class="alert alert-danger">Mmmmh, you can do better</div>';
            break;
        case 'gabibbo':
            echo '<div class="alert alert-danger">How do you know my name?!</div>';
            echo '<style>body{ background: url("gabibbo.jpg") fixed center; background-size: cover } form, h3 {background-color: white}</style>';
            break;
        case 'pretty please':
            include_once('secret.php');
            echo '<div class="alert alert-success">Now we are talking! ' . $FLAG . '</div>';
            break;
        default:
            echo '<div class="alert alert-danger">I don\'t understand you...</div>';
            break;
    }
}
```

Each of the options available from the dropdown menu doesn't let us get the flag; in order to do that, we need to force send the option "pretty please".

## Solution

To send an arbitrary value you can proceed in two ways:

- Modify the page using browser's developer tools (F12 key) to add an option with "pretty please" as a value in the dropdown menu.
- Forge the HTTP request from scratch to send the arbitrary option.

Here is the Python code necessary to perform the request to get the flag and print it.

```python
URL = "http://prettyplease.challs.external.open.ecsc2024.it"
r = requests.post(URL, data={'how': 'pretty please'})
flag = re.search(r'flag{.*}', r.text).group(0)
print(flag)
```
