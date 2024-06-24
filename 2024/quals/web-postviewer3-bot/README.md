# XSS Bot for Postviewer v3

## Internal testing

Need to add bot's IP to the firewall:

```sh
kctf cluster get-src-ip-ranges
# Current IP range: "104.132.0.0/14,74.125.56.0/21,74.125.120.0/22,72.14.224.0/21,34.140.12.195/32,34.22.144.6/32"
xss_bot_ip="34.22.144.6" # from inside container: wget -qO- https://ipecho.net/plain | xargs echo
kctf cluster set-src-ip-ranges "<current_ranges>,${xss_bot_ip}/32"
```
