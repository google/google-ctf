# Postviewer v2 - writeup

## Challenge's overview

> I fixed all the bugs from the last year challenge so it should be secure now. Ri1ght?  
>   
> [Attachment](../attachments/bot.js)  
> https://postviewer2-web.2023.ctfcompetition.com  

From the UI side, the challenge looked exactly like the previous year's [Postviewer](https://gist.github.com/terjanq/7c1a71b83db5e02253c218765f96a710#challenges-overview).

The core change is that:
1. There is no `querySelector` injection anymore but rather the file gets rendered via `document.getElementById`
2. The file is transferred to a new shim via `iframe.contentWindow?.postMessage({ body, mimeType, sandbox}, url.origin)`, where:
   1. `sandbox` is set to `['allow-scripts']`
   2. `url.origin` is a random origin generated on the client-side
3. A new [shim](../challenge/src/sandbox/shim.html) page, that is used to render the file, is hosted on `sbx-<random>.postviewer2-web.2023.ctfcompetition.com/shim.html` origin with `Content-Security-Policy` set to `frame-src: blob:`
4. The main page has `Content-Security-Policy` set to `frame-ancestors *.postviewer2-web.2023.ctfcompetition.com; frame-src *.postviewer2-web.2023.ctfcompetition.com;`
5. [bot.js](../attachments/bot.js) ensures that no popups can be opened and additionally enables [Strict Origin Isolation](https://www.maketecheasier.com/enable-chrome-strict-site-isolation/).


The idea for the challenge was to leak admin's flag.txt file. 

## One vulnerability
Even though the exploit is rather complex, the challenge had only one vulnerability! The vulnerability lies in [shim.html](../challenge/src/sandbox/shim.html). 
Players could notice that `allow-same-origin` is strictly forbidden but the check can be easily bypassed. 

```js
const forbidden_sbx = /allow-same-origin/ig;
...
for(const value of e.data.sandbox){
    if(forbidden_sbx.test(value) || !iframe.sandbox.supports(value)){
        console.error(`Unsupported value: ${value}`);
        continue;
    }
    iframe.sandbox.add(value);
}
```

It's not widely known, but a regular expression with a global flag cannot be used indefinitely. It's due to the behavior that after a first successful match, the `lastIndex` will increase and consecutive searches will yield no matches. 

To bypass the check, players could simply send `sandbox: ['allow-same-origin', 'allow-same-origin', 'allow-scripts']` and hence achieve XSS on any `sbx-*.postviewer2-web.2023.ctfcompetition.com`. However, the flag is rendered on a random origin, so it's not enough to utilize it yet.

## Exploitation idea
The idea of the exploitation is rather straightforward.

1. Calculate the ID of `flag.txt` and open `https://postviewer2-web.2023.ctfcompetition.com/#file-87ebbc317d687eeff47403603cc6dfb9b7d6c817`.
2. Leak the origin of the shim that loaded `flag.txt` in a sandboxed iframe.
3. Embed `<leaked_origin>/shim.html` and execute XSS there.
4. From the embedded XSS, access the shim iframe (shim doesn't have sandbox attributes, only an inner frame does), leak `blob:` URL of the flag, and fetch it. 

### First obstacle - frame-ancestors

The first obstacle was that the main page could only be embedded by `*.postviewer2-web.2023.ctfcompetition.com` ancestors. This means that the page could not be embedded on a player's website. The player was supposed to embed it on `sbx-anything.postviewer2-web.2023.ctfcompetition.com`.

### Second obstacle - frame-src

But then comes the second obstacle - `CSP: frame-src blob:`. Because of the directive, players couldn't easily embed the main page on `sbx-anything` origin. Additionally, the server was supposed to respond with a strict CSP for any other page, e.g. `sbx-anything.postviewer2-web.2023.ctfcompetition.com/not-found` would result in `Content-Security-Policy: default-src 'none'`.


## Exploitation

### No-CSP subpage

Someone that follows my research could find a usefull CSP bypass in one of the [blogposts](https://terjanq.medium.com/arbitrary-parentheses-less-xss-e4a1cf37c13d). The idea is to find a subpage without a CSP and execute the payload there. A trick that usually works is to open a page with a very long url that will be blocked on the intermediate proxy side because of the overlong headers. Embedding `sbx-anything.postviewer2-web.2023.ctfcompetition.com/AAAAA....AAA` would work fine for a long sequence of A's.


### Top-redirection
Because of the blocked popups, a player had to find a way to redirect the top window. These redirections are usually blocked because of the [frame busting](https://chromestatus.com/feature/5851021045661696) protection. There are a couple ways where the top window could allow the iframe to redirect itself. 

1. The most popular way among the players was to use `allow-top-navigation` sandbox flag which makes the iframe be able to redirect the top window. It strangely works as an `allow` policy, but this as well could be a Chrome bug because of the [comment](https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/frame/local_frame.cc;l=1861) that says that the _ancestor chain_ should be respected. 

>    // Top navigation is forbidden in sandboxed frames unless opted-in, and only  
>    // then **if the ancestor chain allowed to navigate the top frame**.  
>    // Note: We don't check root fenced frames for kTop* flags since the kTop*  
>    // flags imply the actual top-level page.  

2. I've become aware of the sandbox technique before the CTF started but the intended way was a bit harder. A window can redirect another window if they are in `openee-opener` relationship. The trick is to call `open('URL', 'iframe')` that will create such a relationship with an iframe named `iframe` (e.g. `<iframe name='iframe'>`). This allows the iframe to redirect its `opener` without user-interaction. 

### Creating a self-containing exploit

1. The attacker sends the admin to `attacker.com`. 
2. In there, the attacker embeds two iframes: 
   1. `sbx-anything.postviewer2-web.2023.ctfcompetition.com/shim.html` used to get XSS
   2. `sbx-anything.postviewer2-web.2023.ctfcompetition.com/AAAA...AAA` used to execute the XSS on a CSP-less subpage and redirect the top-window, let's call it `redirector`
3. The attacker creates a new `blob` document from the `redirector` iframe that contains a self-containg exploit used to leak the flag and then redirects top window to it.
4. The self-containing exploit executes the following steps:
   1. Embed the flag on the main page via `https://postviewer2-web.2023.ctfcompetition.com/#file-87ebbc317d687eeff47403603cc6dfb9b7d6c817`.
   2. Redirect the most inner iframe to `about:blank` (or some other blob) and leak shim's origin via `location.ancestorOrigins` (redirection can be easily done by calling `top[0][0][0].location = 'about:blank'`). 
   3. Spawn a new shim iframe with the leaked origin and set sandbox to `allow-same-origin allow-scripts`.
   4. Execute XSS in that iframe and leak the `blob:` of the flag via `top[0][0].document.querySelector('iframe').src`.
   5. Fetch the flag from the same iframe (as simple as `fetch(leaked_blob_url)`).

A full exploit with comments can be found [here](../solution/solve.html).

**CTF{who_needs_popups_when_you_can_simply_have_it_all}**

## Closing thoughts

The idea behind the challenge comes from a real bypass that I found internally, if we were to allow the `allow-same-origin` sandbox flag in our framing solutions. We've [blogged](https://security.googleblog.com/2023/04/securely-hosting-user-data-in-modern.html) about our approach and this challenge demonstrates how difficult it is to achieve a proper isolation of user content by utilising currently available Web Platform features.