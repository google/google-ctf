

the circuit is a serial register
(`https://en.wikipedia.org/wiki/File:4_Bit_Shift_Register_001.svg`)
made of master-slave d flip flops
(`https://en.wikipedia.org/wiki/File:D-Type_Flip-flop_Diagram.svg`)
where clock is Cin, and input data is A.

when state of the shift register (16 bits) matches a certain pattern,
another flip flop is triggered forever. we craft an input such
that it is triggered only for bit 6 (i.e. 64s)

if triggered and A is 1:
  set C to 1

this backdoor makes it such that if we after triggering,
add something to 64, we additionally add extra 128 for a
total of 192. Thus instead of printing encrypted input,
we print flag.
