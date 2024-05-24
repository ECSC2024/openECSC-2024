# openECSC 2024 - Round 3

## [web] Fuper Fibernetic Interpolator (34 solves)

We are proud to announfe a new verfion of our award winning ftring interpolator! Feel free to try it out through our public beta API! It's INDEFTRUCTIBLE

Site: [http://fuperfiberneticinterpolator.challs.open.ecsc2024.it](http://fuperfiberneticinterpolator.challs.open.ecsc2024.it)

Authors: Vittorio Mignini <@M1gnus>, Simone Cimarelli <@Aquilairreale>

## Solution

We are given partial source code for a common lisp application
implementing a web service. The business logic of the service is
implemented in a POST endpoint under `/interpolate`. By reading the
source code and sending POST requests to the endpoint and analyzing its
detailed error responses we understand we have to send it an
[s-expression](https://en.wikipedia.org/wiki/S-expression) in the
following shape:

```lisp
(:template "A template string with {interpolation} {flags}"
 :substitutions ((:interpolation . "very good")
                 (:flags . "intentions")))
```

The `:substitutions` _association list_ members will be interpolated
into the value of `:template`.

By analyzing the source code further, we can see the parsing of
s-expressions is delegated to the builtin common lisp parser function
`read`, the same being used by the language's compiler, which in common
lisp is available at runtime and can be programmatically invoked. The
common lisp parser `read` has some well known vulnerabilities when
handed with user-controlled input, such as the ability to compile and
evaluate code at read-time when it encounters the magic macro character
sequence [`#.`](http://clhs.lisp.se/Body/02_dhf.htm). This well-known
vulnerability is mitigated by binding the dynamic variable `*read-eval*`
to `nil` (false) before executing the call to `read`, disabling this
potentially harmful behavior. Common lisp's input syntax can be heavily
modified by operating on an internal data structure called the
`*readtable*` and other configuration variables; it is therefore common
to execute calls to `read` that must handle data in an external
representation in the context of the `with-standard-io-syntax` "context
manager" macro. This ensures that reasonable default are in place when
reading data coming from other systems, for example over the internet.
An often overlooked side-effect of `with-standard-io-syntax`, though, is
resetting `*read-eval*` to its default `t` (true).
`(with-standard-io-syntax ...)` and `(let ((*read-eval* nil)) ...)`
should therefore appear in this exact order for the program to be safe;
the authors of the Interpolator have flipped them by mistake, rendering
the service vulnerable to read-time evaluation attacks. We test out
guess by writing and testing an attack payload:

```lisp
(:template "{test}"
 :substitutions ((:test . #.(concatenate 'string "Hello " "world!"))))
```

The server answers with `Hello world!`, and the service is vulnerable.

We try to extract the value of the `*flag*` global variable that we see
redacted in the provided source, and we learn we have to prefix it with
an explicit package specifier because the read-eval expression is not
being evaluated in the context of the same package as the source code
(`:app.web`). The `*flag*` symbol is not publically exported, but common
lisp allows us to access it anyways by doubling the colon between the
package and symbol names:

```lisp
(:template "{flag}"
 :substitutions ((:flag . #.app.web::*flag*)))
```

By writing the payload this way, it is as if we had sent the flag itself
in the body of the POST request to the `/interpolate` endpoint,
therefore the flag value undergoes the same safety checks that regular
user input is subject to. One of the validation rules prohibits curly
brace characters `{` and `}` in substitution texts to avoid multiple
(possibly recursive) interpolations, but the flag format containts those
characters. To allow the flag to pass all validity checks for
interpolation into `:template`, we can transform it using standard
common lisp functions in various ways, for example substituting the
prohibited characters for other acceptable ones, or by encoding the
whole string in a different representation, such as a base16 string as
demonstrated in the following example:

```lisp
(:template "{hexflag}"
 :substitutions ((:hexflag . #.(format nil "~{~A~}"
                                 (map 'list
                                      (lambda (c)
                                        (write-to-string (char-code c) :base 16))
                                      app.web::*flag*)))))
```

The encoded flag is successfully interpolated into the template string
and reflected to us in the server's response. We can now decode the
flag using python or other standard tools.
