# Timing some AVR

To run: `make run` or `./simduino.elf code.hex`.

This is a challenge that requires user to exploit
some lesser known feature of AVR: "interrupt buffering",
so to say (that a timer interrupt will fire even if the
corresponding timer is disabled - and had been disabled
while interrupts were disabled globally; the requirement
is that the timer set the interrupt bit before it was disabled).
Another feature of AVR used in this challenge is weird
`sei` behavior: it enables interrupts, but the very next
instruction is still executed before any pending interrupts.
This allows makes the `logged_in = 1` statement to execute
before timer interrupt.

There's also a first stage of this challenge, in which
you have to build a simple timing side channel to
find the password - this stage is really only used
to allow fine control over timing for the race condition.

