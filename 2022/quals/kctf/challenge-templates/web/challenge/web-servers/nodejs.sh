#!/bin/bash

# Start node web server
(&>/dev/null node /web-apps/nodejs/app.js)&

# Proxy stdin/stdout to web server
socat - TCP:127.0.0.1:8080,forever
