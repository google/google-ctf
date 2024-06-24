# Hackceler8 2023 Game

## Steps to run the game:

1. Install prerequisites
```
cd hackceler8-2023
python3 -m venv my_venv
cd game/
source ../my_venv/bin/activate
pip3 install -r requirements.txt


2. Run server (optional but good for testing cheat detection/etc.)

```
cd hackceler8-2023/game
source ../my_venv/bin/activate
mkfifo server_pipe
nc -l 127.0.0.1 8888 < server_pipe  | python3 server.py > server_pipe
```

3. Run client

```
cd hackceler8-2023/game
source ../my_venv/bin/activate
python3 client.py 127.0.0.1 8888 --nopow
```

If you want to run the client without a server, pass `--standalone` as additional argument.

4. Run client on the live server:
```
 python3 client.py h8-teaser.2024.ctfcompetition.com 1337
```
