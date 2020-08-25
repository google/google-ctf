# The DevMaster Sandboxed Programming Language: Creating unintentional bugs since 2019™

After our last disaster with a sandboxed build system, we've decided to pivot. We've created a sandboxed programming language with userland thread support. Why userland threads? Because they're fast! (Benchmark results pending.)

With this language, you can write code that's safe to run anywhere. Those executing your code can trust that it won't ever be able to read their precious `./flag` files.

(Legal notice: 'can trust' may not be equivalent to 'should trust.' DevMaster Industries disclaims all liability resulting from running code written in the DevMaster Sandboxed Programming Language.)

# Challenge Details

In this challenge, you are given a sandboxed programming language with a
userland threading library, and must find a vulnerability to break out of the
sandbox.

A few important notes:

*   The intended vulnerablity is somewhere in the `threading` directory, and it
    is not in the "signals.cc" or "build.sh" files. Source code to the compiler
    and runtime are provided; however, they are not required to complete the
    challenge.
*   The `signals.cc` file internally uses SIGUSR1 and SIGUSR2 for managing
    thread wakeup and preemption. If using gdb, you may wish to run
    `handle SIGUSR1 nostop noprint` and `handle SIGUSR2 nostop noprint`.
*   The threading library is functional as a standard C++ library. We recommend
    you look for the vulnerability using C++, and don't switch to the sandboxed
    programming language until after you've found the bug. You can consider
    `thread.h` and `semaphore.h` to be the public interface of the threading
    library. Be sure to build with pthreads enabled.
*   The compiler builds with `-z execstack` and `-fno-stack-protector`, for
    maximum exploitability.

The challenge server accepts .simp source code, and runs in two modes: "build
and download" or "build and run". You'll use the "build and run" mode to solve
the challenge; however, "build and download" is provided so that you can ensure
your binary is built in exactly the same environment as the server, should you
find that useful. You can use client.cc to easily communicate with the server.
server.cc is provided, but its implementation is irrelevant to the intended
solution. Binary versions of client and server are also provided.
