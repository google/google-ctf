Example XSS Bot

This is based on the challenge skeleton with a few modifications:
* Disable nsjail in the cmd line (Dockerfile) and remove the nsjail config
* Create a tmpfs at /tmp via k8s/containers.yaml
* Modify the Dockerfile to install puppeteer
* Add secrets/cookie and remove the flag
* Add the puppeteer script in files/bot.js
