Note that you need to provide OAUTH2 credentials to be used by the chat bot in
the form of `client_secret.json` and `oauth_credentials.json` files.

The whole process is rather painful and you really need to refer to
documentation on how to do that:

  * https://developers.google.com/youtube/v3/getting-started

Note that due to how the YT chat API is designed (you need to call the chat API
every few seconds) and because it actually costs around 5 quota units to do a
call, you need A LOT of API quota for the bot (200k/day advised; 60k/day doable
in the slow mode - see `voting_config.py`). The quota usage can be greatly
decreased if you don't mind losing "interactive" features like live voting
graph and so on.

Also, make the YouTube channel few days earlier and start testing livestreaming
as soon as possible - there are a lot of hoops to jump through to get everything
verified and approved in a new channel.
