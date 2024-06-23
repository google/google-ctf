# Postviewer v3 writeup by [@terjanq](https://twitter.com/terjanq)

As it always have been with my challenges for Google CTF, they are based
on real bugs I found internally. This year is a bit different though. This time the
bugs were crafted by no other than me myself. One bug didn't manage to reach the
production and the other is still present in prod making it effectively a 0day!

Both of my challenges (Postviewer v3 & Game Arcade) for this year are are related
to a sandboxing I've been working since the first postviewer challenge. You can
read a little bit about it in
[here](https://web.dev/articles/securely-hosting-user-data#approach_2_serving_active_user_content).

## Intro

> POSTVIEWER V3 &nbsp;&nbsp;&nbsp;&nbsp; [308pt]
>
> New year new postviewer.
>
> https://postviewer3-web.2024.ctfcompetition.com\
> Solved by (18):\
> Friendly Maltese Citizens, DiceGang, BlueWater and more.

Similarly to other Postviewer challenges, a player is welcomed with a simple
client-side application where they can store and render some files.

Each file is rendered in an shim iframe hosted on a unique origin that is directly
connected to the contents of the file. This ensures that file A will be protected
by Same Origin Policy from a file B.

The goal of the challenge is to find a way to leak admin's file containing the flag.

## Shim iframe

Each shim iframe is rendered at a unique origin at the below URL

```
https://sbx-<hash>.postviewer3-web.2024.ctfcompetition.com/product/shim.html?origin=https://postviewer3-web.2024.ctfcompetition.com
```

where hash is calculated in the following way

```js
hash = sha256(fileBody + product + origin + salt)
```

Shim iframe receives a file to render (`fileBody`) together with `mimeType` and `salt`
over postMessage communication. The `product` and `origin` are both  stored in
the URL. The `origin`'s role is to reject any communication coming from a
different origin but also to ensure that a `malicious.site` can't embed a static
file on the same origin as the Postviewer v3 app.

After the origin check, the `shimIframe` calculates the hash from the received `fileBody`
and `salt` and compares it to the hash stored in the hostname. If it matches
it will redirect itself to a blob document created from the `fileBody` and `mimeType`.

Salt is used to randomize the origin, it's explained in the next section.

## EvaluatorHtml

All files stored in a local database are rendered by the same loader called `evaluatorHtml`.
This is basically another shim iframe which purpose is to evaluate untrusted code.

First, the postViewer app renders `evaluatorHtml` with `salt` set to `location.href`.
The choice of salt is to pin the evaluator's origin to the rendered file, whose
sha1(name) is present in the URL fragment - `file-<sha1(filename)>`. Then it sends
a small JS snippet (together with a file to render) which inserts the file as a blob iframe.

`evaluatorHtml`:

```html
<html>
  <head>
    <meta charset="utf-8">
    <title>Evaluator</title>

    <script>
      onmessage = e => {
        if(e.source !== parent) {
          throw /not parent/;
        };
        if(e.data.eval){
          eval(e.data.eval);
        }
      }
      onload = () => {
        parent.postMessage('loader ready','*');
      }
    </script>

    <style>
      body{
        padding: 0px;
        margin: 0px;
      }
      iframe{
        width: 100vw;
        height: 100vh;
        border: 0;
      }
      .spinner {
        background: url(https://storage.googleapis.com/gctf-postviewer/spinner.svg) center no-repeat;
      }
      .spinner iframe{
        opacity: 0.2
      }
    </style>
  </head>
  <body>
    <div id="container" class="spinner"></div>
  </body>
</html>
```

## Unsafe hashing

As a careful reader could potentially already spot, the hashing function is unsafe.
For two reasons:

1. It concatantes strings without a delimiter.
2. A dynamic part (`salt`) that can be controlled by an attacker is at the end.

Let's follow a simple example to illustrate the issue in which different files
will result in the same hash and hence with the same shim origin.

```js
sha256("fileBody" + "product" + "origin" + "abcdef") === sha256("fileBodyproduct" + "" + "abcdef" + "")
```

The intended solution was to notice that the `evaluatorHtml` can be split on
the `https://storage.googleapis.com` string. Then, a collision would be possible
with the following values:

```js
  body == evaluatorHtml.split('https://storage.googleapis.com')[0]
  product = ''
  origin = 'https://storage.googleapis.com'
  salt == evaluatorHtml.split('https://storage.googleapis.com')[1] +
          'postviewer' + 'https://postviewer3-web.2024.ctfcompetition.com/' +
          'https://postviewer3-web.2024.ctfcompetition.com/#aaaaaaaaaaa'
```

Pathname must follow the following regex, where the capturing group is the `product`:
`/[/]([a-z0-9_-]*)[/]shim.html/`. It's possible to render as an empty product
at `https://postviewer3-web.2024.ctfcompetition.com/a//shim.html`.

Everyone can host their files at `storage.googleapis.com` by simply uploading
some public files to [Cloud Storage](https://cloud.google.com/storage). It requires
adding billing information though which players do not like. Alternative way
is to find an XSS there, and that's what I did in a couple of minutes
[https://storage.googleapis.com/vrview/2.0/index.html?image=&lt;style/onload=alert()&gt;](https://storage.googleapis.com/vrview/2.0/index.html?image=%3Cstyle/onload=alert()%3E)

This was the core idea of the challenge but unfortunately by wanting to introduce
a race-condition part and having an unpredictable flag filename, I introduced an
easier unintended solution. Players could achieve the collistion by forcing
the application to set a custom `salt` (intended) but fully controlled
(unintended) which can be used smuggle the origin of player exploits quite easily.


## Race-condition

Since the admin's file has an unpredictable name players had to either leak the
name somehow or influence it in order to calculate the collistion hash. The former
shouldn't be possible, and the latter could be done with some race-condition.

The postviewer application has a support for previewing a file via numeric value
after whihc it will replace it with the file hash since the order of files might
change. E.g. `#0` might become `#file-87ebbc317d687eeff47403603cc6dfb9b7d6c817`
and only the latter value would be used in `salt`. Players could dynamically
change the hash of the postviewer app so that they will smuggle their known
string in the following flow:

```js
setTimeout(()=>{winRef.location = "https://postviewer3-web.2024.ctfcompetition.com/#0"}, 100)
setTimeout(()=>{winRef.location = "https://postviewer3-web.2024.ctfcompetition.com/#aaaaaaaaaaa"}, 101)
```

and with a little bit of luck they will win the race and `#aaaaaaaaaaa` will be
used in `salt` instead of the unpredictable `#file-87ebbc317d687eeff47403603cc6dfb9b7d6c817`.

## Exploit

After winning the race and hosting the exploit at `storage.googleapis.com` the
players could access the shimIframe (because it's same-origin), read the inner
iframe blob src, fetch it and read the flag.

You can check out the full [exploit](solution/solve.html), which is also thoroughly commented.


## Closing thoughts

There is always a little dissatification when your challenge can be solved in an
easier way than intended, but I think it didn't make the challenge that much less
interesting. After all, it was based on a real bug which could be exploited
in two different ways, I just missed the other attack scenario. Funnily enough,
the unintended vulnerability would have a similar impact on our products as the
intended one if the bug had not been fixed.

These CTF challenges and bugs show just how difficult it is to write a secure
code, even for Security Engineers. Bugs are lurking everywhere from left to right.

If you enjoyed the writeup, check out my writeups for previous editions!

- [Security Driven](https://gist.github.com/terjanq/458d8ec1148e96f7ccbdccfd908c56f6)
- [Postviewer](https://gist.github.com/terjanq/7c1a71b83db5e02253c218765f96a710)
- [Postviewer v2](https://github.com/google/google-ctf/blob/main/2023/quals/web-postviewer2/solution/README.md)
