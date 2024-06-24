# Solver

`solver.go` contains a solver to the challenge. It requies two parameters:

- `--challenge-url` - the base URL of the challenge
- `--solver-url` - the public URL of the solver

It can be run with:

```bash
go run solver.go --challenge-url <URL> --solver-url <ANOTHER_URL>
```

The solver will set up a server, connect to the challenge, and then retrieve the flag.
