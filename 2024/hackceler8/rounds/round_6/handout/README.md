# Hackceler8 2024 Game

## Steps to run the game:

1. Install prerequisites
```
cd hackceler8-2024-game
python3 -m venv my_venv
source my_venv/bin/activate
pip3 install -r requirements.txt
```

2. Run server (optional but good for testing cheat detection/etc.)

```
cd hackceler8-2024-game
source my_venv/bin/activate
python3 server.py
```

To test the obstacles that will potentially be enabled this round, add
`--extra-items "Minion hat" "Random gate pin"`

3. Run client

```
cd hackceler8-2024-game
source my_venv/bin/activate
python3 client.py
```

If you want to run the client without a server, pass `--standalone` as an additional argument.
