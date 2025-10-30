.code
s.ldw #0x1234

// stack instruction - push 0x10 onto the stack
S.LDB #0x10
S.lDb #0x10
s.ldb #16

// register instruction - move 42 into A
R.MOV A, #0x2A
R.MOV A, #0x2a
r.MoV A, #42

r.mov a, b
s.pop
r.mov a, @0x1234 
s.pop

some_thing:
R.SYS

R.JMP some_thing
R.JMP @0x1234
R.JMP @5678

// push the addr of the data at label `prompt` to the stack
S.LDP prompt

R.HLT

.data
prompt: "Welcome to multiarch!"
encdata: "\xaa\xbb\xcc\xdd"
