# License of this file

Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Author: Kegan Thorrez

# empty ls XSS bot

This bot will read a url from the network and then connect to it using chrome
(puppeteer). It immediately responds over the network before connecting to the
url. This is to let the requester know that the bot is running without using
a lot of the requester's time.

This is a separate "challenge" from web-empty-ls in order to prevent SSRF on the
metadata server that web-empty-ls has using web-empty-ls's service account.
