# All the little things

## Overview

This is a client-side challenge whose goal is to connect smaller vulnerabilities
into a full XSS on the page. The user will have an ability to create private
notes not visible to other users. The XSS will not be obvious and will require
various techniques such as prototype pollution and DOM Clobbering to achieve DOM
XSS. The bot will imitate another user who stored a secret flag in a note.

## Proof of concept

The exploit can be found in [./exploit/run.sh](./exploit/run.sh)


## Metadata

```json
{
    "challenge": {
      "name": "All the little things",
      "description": "I left a little secret in a note, but it's private, private is safe.\n\nNote: TJMike🎤 from Pasteurize is also logged into the page.",
      "identifier": "littlethings",
      "category": "web",
      "points" : 500,
      "flag": "CTF{When_the_w0rld_c0mes_t0_an_end_all_that_matters_are_these_little_things}",
      "released": true,
      "gae": {
          "app_config": "app/app.yaml",
          "dns-part": "littlethings"
      },
      "link": "https://littlethings.web.ctfcompetition.com"
    }
  }
```