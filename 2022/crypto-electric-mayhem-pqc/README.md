# Remote power analysis challenge - Post Quantum Crypto edition

The server presents power traces of a secret firmware crypto operation. The goal is to recover the secret key.

![Screenshot1](challenge/power_trace_screenshot.png)

## Design

The [firmware](challenge/firmware/main.c) runs under an enhanced ARM-M0 emulator called [ELMO](https://github.com/sca-research/ELMO). ELMO extends [thumbulator](https://github.com/dwelch67/thumbulator) with a model that estimates the power consumption of individual thumb instructions.

Access to sufficiently accurate power traces allows an attacker to mount [power analysis](https://en.wikipedia.org/wiki/Power_analysis) attacks, such as [Correlation Power Analysis](https://wiki.newae.com/Correlation_Power_Analysis) (CPA), or differential Power Analysis (DPA). See [healthcheck.py](healthcheck/healthcheck.py) for details.

Attack is inspired by the paper ["Side-Channel Analysis of Lattice-Based Post-Quantum Cryptography: Exploiting Polynomial Multiplication"](https://ia.cr/2022/474) by Catinca Mujdei, Arthur Beckers, Jose Maria Bermudo Mera, Angshuman Karmakar, Lennert Wouters and Ingrid Verbauwhede.

## How to rebuild the challenge artifacts

```
$ git submodule update --init
$ make -C challenge clean all
```

## How to re-flag

Update `challenge/flag`, rebuild challenge artifacts using `make -C challenge`, and restart the challenge using `kctf chal start`.

## How to debug healthcheck.py

Disable the `healthcheck` in `challenge.yaml`, and re-deploy the server:

```
$ kctf chal start
```

Start port-forwarding to the challenge container:

```
$ kctf chal debug port-forward
[*] starting port-forward, ctrl+c to exit
Forwarding from 127.0.0.1:XXXXXX -> 1337

```

Run `healthcheck.py` and connect to the forwarded port:

```
$ cd healthcheck
$ python3 healthcheck.py --port XXXXXX --capture traces.json.gz
```

In addition, you can examine the logs using `kubectl logs [electric-mayhem-container] -c healthcheck`. A successful run should print the following:

```
Unpacking 200 ciphertexts
Unpacking hint secretkey
Guessing SK[1]: 100%|██████████| 3329/3329| (-0.9274714769557206, 1834, 17)
Result: best guess for sk coeff 1 is deque([(-0.9274714769557206, 1834, 17), (-0.9158466759734244, 2285, 13), (-0.9038146465878589, 2285, 14)], maxlen=3)
Guessing SK[0]: 100%|██████████| 3329/3329| (-0.7408274265512077, 775, 33)
Result: best guess for sk coeff 0 is deque([(-0.7408274265512077, 775, 33), (-0.5759228719654801, 0, 33), (-0.4983275343446943, 0, 31)], maxlen=3)
ok
```
