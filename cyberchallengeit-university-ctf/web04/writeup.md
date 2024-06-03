# CyberChallenge.IT 2024 - University CTF

## [web] Sharepic (12 solves)

Try out this brand new and super original social network! We're still working on implementing some features, like... every social feature...

Site: [http://sharepic.challs.external.open.ecsc2024.it:38211](http://sharepic.challs.external.open.ecsc2024.it:38211)

Author: Lorenzo Leonardini <@pianka>

## Solution

Sharepic is a picture sharing social network.

The whole challenge revolves around an nginx misconfiguration. From the [official wiki](https://web.archive.org/web/20240514122031/https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/#passing-uncontrolled-requests-to-php) we can read

> the default PHP configuration tries to guess which file you want to execute if the full path does not lead to an actual file on the filesystem.
>
> For instance, if a request is made for /forum/avatar/1232.jpg/file.php which does not exist but if /forum/avatar/1232.jpg does, the PHP interpreter will process /forum/avatar/1232.jpg instead. If this contains embedded PHP code, this code will be executed accordingly.

So the basic idea is to create a .jpg file with some php in the comment, upload it and go to `/image.jpg/asd.php`. The code needs to connect to the database in order to dump the flag:

```php
<?php
require_once '../components/db.php';
var_dump($db->query('SELECT flag FROM secrets')->fetchAll());
exit;
?>
```
