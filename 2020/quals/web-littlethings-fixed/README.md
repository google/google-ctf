# All the fixed things

## Overview

This is a fixed version of the `All the little things` that contained an unintended vulnerability in `/static/debug.js` file. This was not released during the competition. 

## Proof of Concept

The exploit can be found in [./exploit/run.sh](./exploit/run.sh)

## metadata

```json
{
    "challenge": {
      "name": "All the fixed things",
      "description": "Developing challenges is hard. Can you crack the fixed version of All the little things?\n\nNote: this challenge was not released during the CTF",
      "identifier": "fixedthings",
      "category": "web",
      "points" : 500,
      "flag": "CTF{twitter.com/terjanq}",
      "released": true,
      "visible": false,
      "gae": {
          "app_config": "app/app.yaml",
          "dns-part": "fixedthings-vwatzbndzbawnsfs"
      }
    }
  }
```