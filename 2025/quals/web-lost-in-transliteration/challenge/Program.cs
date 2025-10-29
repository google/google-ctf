// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Text;
using System.Web;
using System.Text.RegularExpressions;
using System.Net.Mime;
using System.Globalization;
using System.Diagnostics;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton(new SemaphoreSlim(MAX_BROWSERS, MAX_BROWSERS));
var app = builder.Build();

Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

static bool IsValidContentType(string contentType)
{
  if (!ContentTypeRegex().IsMatch(contentType))
  {
    return false;
  }
  try
  {
    _ = new ContentType(contentType);
  }
  catch
  {
    return false;
  }
  return true;
}


app.MapGet("/", (string q = "", string ct = "") =>
{
  return Results.Text($@"
        <!doctype html><meta charset=utf-8>
        <body>
        <link href='https://fonts.googleapis.com/css2?family=Palatino+Linotype&amp;display=swap' rel='stylesheet'>
        <link rel=stylesheet href='/file?filename=style.css&amp;ct=text/css'>
        <script type=module src='/file?filename=script.js&amp;q={HttpUtility.UrlEncode(q)}&amp;ct=text/javascript'></script>
      ",
      contentType: "text/html");
});

app.MapGet("/file", (string filename = "", string? ct = null, string? q = null) =>
{
  string? template = FindFile(filename);
  if (template is null)
  {
    return Results.NotFound();
  }
  ct ??= "text/plain";
  if (!IsValidContentType(ct))
  {
    return Results.BadRequest("Invalid Content-Type");
  }
  string text = template
      .Replace("TEMPLATE_QUERY_JS", JsEncode(q));
  return Results.Text(text, contentType: ct);
});

static async Task<IResult> xssBot(string url)
{
  if (!url.StartsWith("http://localhost:1337/"))
  {
    return Results.BadRequest("url must start with http://localhost:1337/");
  }
  var info = new ProcessStartInfo
  {
    FileName = "/home/user/bot.mjs",
    CreateNoWindow = true,
    RedirectStandardError = true,
    RedirectStandardOutput = true,
    UseShellExecute = false,
  };
  info.ArgumentList.Add(url);

  using var process = new Process { StartInfo = info };
  process.Start();
  var stdoutTask = process.StandardOutput.ReadToEndAsync();
  var stderrTask = process.StandardError.ReadToEndAsync();

  var cancel = new CancellationTokenSource();
  cancel.CancelAfter(TimeSpan.FromSeconds(20));
  var exitTask = process.WaitForExitAsync(cancel.Token);
  try
  {
    await Task.WhenAll(exitTask, stdoutTask, stderrTask);

    // For debugging
    await Console.Out.WriteLineAsync("STDOUT:");
    await Console.Out.WriteLineAsync(await stdoutTask);
    await Console.Out.WriteLineAsync("\n\nSTDERR:");
    await Console.Out.WriteLineAsync(await stderrTask);
  }
  catch (OperationCanceledException)
  {
    return Results.BadRequest("operation canceled");
  }

  if (process.ExitCode == 0)
  {
    return Results.Text("OK");
  }
  else if (process.ExitCode == 124)
  {
    return Results.BadRequest("timed out");
  }
  else
  {
    return Results.BadRequest("something went wrong, see console for details");
  }
}

app.MapGet("/xss-bot", async (string url, SemaphoreSlim semaphore) =>
{
  await semaphore.WaitAsync();
  try
  {
    return await xssBot(url);
  }
  finally
  {
    semaphore.Release();
  }
});

app.Run("http://0.0.0.0:1337/");

partial class Program
{
  [GeneratedRegex("^text/", RegexOptions.IgnoreCase)]
  private static partial Regex ContentTypeRegex();

  private static readonly int MAX_BROWSERS = 10;

  private static string? FindFile(string filename)
  {
    return filename switch
    {
      "script.js" => TEMPLATE_JS,
      "style.css" => TEMPLATE_CSS,
      _ => null,
    };
  }

  private static bool IsSafeChar(char c)
  {
    var cat = char.GetUnicodeCategory(c);
    // We don't consider ModifierLetter safe.
    var isLetter = cat == UnicodeCategory.LowercaseLetter ||
                   cat == UnicodeCategory.UppercaseLetter ||
                   cat == UnicodeCategory.OtherLetter;

    return isLetter || char.IsWhiteSpace(c);
  }

  private static string JsEncode(string? s)
  {
    if (s is null)
    {
      return "";
    }
    var sb = new StringBuilder();
    foreach (char c in s)
    {
      if (IsSafeChar(c))
      {
        sb.Append(c);
      }
      else
      {
        sb.Append("\\u");
        sb.Append(Convert.ToInt32(c).ToString("x4"));
      }
    }
    return sb.ToString();
  }


  private static readonly string TEMPLATE_JS = @"
// Load Lit directly from the CDN.
import {
  LitElement,
  html,
} from 'https://cdn.jsdelivr.net/gh/lit/dist@3/core/lit-core.min.js';

function transliterateGreekToLatin(text) {
    const greekMap = {
                '\u03b1': 'a', '\u03b2': 'b', '\u03b3': 'g', '\u03b4': 'd', '\u03b5': 'e', '\u03b6': 'z', '\u03b7': 'i', '\u03b8': 'th',
                '\u03b9': 'i', '\u03ba': 'k', '\u03bb': 'l', '\u03bc': 'm', '\u03bd': 'n', '\u03be': 'x', '\u03bf': 'o', '\u03c0': 'p',
                '\u03c1': 'r', '\u03c3': 's', '\u03c2': 's', '\u03c4': 't', '\u03c5': 'y', '\u03c6': 'f', '\u03c7': 'ch', '\u03c8': 'ps',
                '\u03c9': 'o',
                '\u03ac': 'a', '\u03ad': 'e', '\u03ae': 'i', '\u03af': 'i', '\u03cc': 'o', '\u03cd': 'y', '\u03ce': 'o',
                '\u03ca': 'i', '\u03cb': 'y',
                '\u0391': 'A', '\u0392': 'B', '\u0393': 'G', '\u0394': 'D', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'I', '\u0398': 'Th',
                '\u0399': 'I', '\u039a': 'K', '\u039b': 'L', '\u039c': 'M', '\u039d': 'N', '\u039e': 'X', '\u039f': 'O', '\u03a0': 'P',
                '\u03a1': 'R', '\u03a3': 'S', '\u03a4': 'T', '\u03a5': 'Y', '\u03a6': 'F', '\u03a7': 'Ch', '\u03a8': 'Ps',
                '\u03a9': 'O',
                '\u0386': 'A', '\u0388': 'E', '\u0389': 'I', '\u038a': 'I', '\u038c': 'O', '\u038e': 'Y', '\u038f': 'O',
                '\u03aa': 'I', '\u03ab': 'Y'
    };

    let transliteratedText = '';
    for (let i = 0; i < text.length; i++) {
        const char = text[i];
        transliteratedText += greekMap[char] || char;
    }
    return transliteratedText;
}

// Main component, available as <greek-transliteration-app>.
class GreekTransliterationApp extends LitElement {
    static properties = {
        greekText: { type: String },
        latinText: { type: String },
    };

    // Constructor to initialize properties
    constructor() {
        super();
        this.greekText = '';
        this.latinText = '';
    }

    // Override createRenderRoot to prevent Lit from creating a shadow root.
    // This makes the component render directly into the DOM.
    createRenderRoot() {
        return this;
    }

    /**
      * Handles input changes and triggers transliteration.
      * @param {Event} event The input event object.
      */
    handleInputChange(event) {
        this.greekText = event.target.value;
        this.latinText = transliterateGreekToLatin(this.greekText);

        const url = new URL(window.location.href);
        url.searchParams.set('q', this.greekText);
        window.history.replaceState({}, '', url.toString());
    }

    // Render method defines the component's UI
    render() {
        return html`
            <div class='container'>
                <h1>Greek to Latin Transliterator</h1>

                <input
                    type='text'
                    autofocus
                    .value='${this.greekText}'
                    @input='${this.handleInputChange}'
                    placeholder='Enter Greek text here...'
                >
                <p class='example-text'>Examples: &Pi;&upsilon;&theta;&alpha;&gamma;&omicron;&rho;&alpha;&sigmaf;, &Sigma;&omega;&kappa;&rho;&alpha;&tau;&eta;&sigmaf;, &Alpha;&rho;&iota;&sigma;&tau;&omicron;&tau;&epsilon;&lambda;&eta;&sigmaf;</p>

                <div style='margin-top: 10px;'>
                    <span class='output-label'>Latin Transliteration:</span>
                    <div id='outputBox'>${this.latinText}</div>
                </div>
            </div>
        `;
    }
}

// Register the custom element
customElements.define('greek-transliteration-app', GreekTransliterationApp);

// Load the query from request.
// TODO: Maybe we should move this directly to HTML into a <script> tag?
window.q = 'TEMPLATE_QUERY_JS';

// XSS prevention
const PAYLOADS = [`<script>`, `</script>`, `javascript:`, `onerror=`];
for (const payload of PAYLOADS) {
  if (window.q.toLowerCase().includes(payload)) {
    throw new Error('XSS!');
  }
}

// TODO: Why don't we just create <main-app> in the HTML?
const mainApp = document.createElement('greek-transliteration-app');
mainApp.greekText = window.q;
mainApp.latinText = transliterateGreekToLatin(window.q);
document.body.appendChild(mainApp);
";

  private static readonly string TEMPLATE_CSS = @"
greek-transliteration-app {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-color: #F0F8FF;
            font-family: 'Palatino Linotype', Palatino, serif;
            padding: 20px;
            box-sizing: border-box;
        }

        .container {
            background-color: #FFFFFF;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
            width: 100%;
            max-width: 650px;
            text-align: center;
            border: 2px solid #0056b3;
            position: relative;
            overflow: hidden;
        }

        h1 {
            color: #0D47A1;
            margin-bottom: 30px;
            font-size: 2.2em;
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }

        input {
            width: calc(100% - 24px);
            padding: 12px;
            margin-bottom: 25px;
            border: 1px solid #80B0D0;
            border-radius: 6px;
            font-size: 1.1em;
            box-sizing: border-box;
            color: #333;
            background-color: #FDFDFD;
        }

        .output-label {
            font-weight: bold;
            display: block;
            margin-bottom: 12px;
            color: #0D47A1;
            text-align: left;
            font-size: 1.1em;
        }

        #outputBox {
            background-color: #E0F2F7;
            border: 1px solid #4CAF50;
            padding: 20px;
            min-height: 70px;
            border-radius: 6px;
            word-wrap: break-word;
            text-align: left;
            font-size: 1.15em;
            color: #1A1A1A;
            line-height: 1.5;
        }

        .example-text {
            font-size: 0.95em;
            color: #555;
            margin-top: -15px;
            margin-bottom: 30px;
            text-align: left;
            font-style: italic;
        }
";

}