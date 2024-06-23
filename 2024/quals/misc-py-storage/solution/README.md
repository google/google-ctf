# Python Storage

## Key idea

The solution for the challenge relies on the fact that python implements a so
called *Universal Newline* to address the newline difference across platforms.

If you're interested in the detail, you can refer to pep-278, but the basic
idea is that no matter what platform the python is on, it will always regards
the following three sequences as newline by default:

1. CR LF (Windows)
2. LF (Unix)
3. CR (Old Macintosh)

Most of the common systems nowadays include at least the LF in its newline
sequence, so it is easy to overlook that CR alone could be a newline and is in
fact built into any common python release.

## Solution

When validating the key/value pair to insert into the database, the
implementation checks whether there's a LF inside the sequence. The intention
is to confine a single entry into a single line, so the logic to enumerate
entries is basically enumerating lines.

Unfortunately, as a CR is regarded as newline as well, it is totally possible
to insert an entry which will then be parsed as two entries later on. As a
result, the permission check guarding secret entry can be bypassed and we're
free to modify the password without authorization.

Once we have control over password, revealing flag is no sweat.

Here's a sample request (before encoding) to overwrite the password:
```
add x x\rsecret_password:x
```
