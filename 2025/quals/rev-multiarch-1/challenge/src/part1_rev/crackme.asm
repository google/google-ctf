.code

start:
    s.ldb sizeof(intro_msg)
    s.ldd intro_msg
    s.ldb #2
    s.sys

chal1:
    s.ldb sizeof(chal1_prompt)
    s.ldd chal1_prompt
    s.ldb #2
    s.sys

    s.ldb #0
    s.sys

    s.ldw #0x1337
    s.ldw #1337
    s.ldd #0x8675309
    s.xor
    s.add

    s.ldd #0xaaaaaaaa
    s.cmp
    s.jne fail

chal2:
    r.mov a, #2
    r.mov b, &chal2_prompt
    r.mov c, sizeof(chal2_prompt)
    r.sys

    // get 0x20 bytes of user input
    r.sub sp, #0x20
    r.mov b, sp
    r.push b
    r.mov c, #0x20
    r.mov a, #1
    r.sys

    r.pop a
    r.mov b, #0x20
    r.call chal2_strhash
    r.cmp a, #0x7331
    r.jne fail

chal3:
    r.mov a, #0
    s.ldb sizeof(chal3_prompt)
    s.ldd chal3_prompt
    s.ldb #2
    s.sys
    r.sys

    r.mov b, a
    r.mov a, #3
    r.sys

    r.mov c, #0

    c3_iter:
    r.call chal3_getval

    r.push #0xffffff
    r.push a
    s.and
    s.ldd #0xc0ffee
    s.cmp
    s.jeq win
    r.add c, #1
    r.cmp c, #10
    r.jeq fail
    r.jmp c3_iter

win:
    r.mov c, sizeof(win_msg)
    r.mov b, &win_msg
    r.mov a, #2
    r.sys
    s.ldb #5
    s.sys
    s.jmp end

fail:
    r.mov c, sizeof(fail_msg)
    r.mov b, &fail_msg
    r.mov a, #2
    r.sys

end:
    r.hlt

// A=ptr, B=sz
chal2_strhash:
    r.mov c, a
    r.add a, b
    r.push a  // push the end pointer to the stack
    r.mov b, #0

    // take 4 bytes
    // mul it against idk
    // take the high 32bits
    // xor against the answer
    // repeat
    c2s_op:
    r.mov d, *c
    r.mul d, #0xcafebabe
    r.xor b, d
    r.pop a
    r.push a
    r.cmp a, c
    r.jeq c2s_done
    r.add c, #4
    r.jmp c2s_op

    c2s_done:
    r.mov a, b
    r.ret #1

chal3_getval:
    r.mov a, #0x00133700
    s.ldb #4
    s.sys
    r.pop b
    r.xor a, b
    r.push a
    s.ldd #0xf2f2f2f2
    s.xor
    r.pop a
    r.ret #0

.data

intro_msg: "Welcome to the multiarch of madness! Let's see how well you understand it.\n"
fail_msg: "Seems like you have some learning to do!\n"
win_msg: "Congrats! You are the Sorcerer Supreme of the multiarch!\n"
chal1_prompt: "Challenge 1 - What's your favorite number? "
chal2_prompt: "Challenge 2 - Tell me a joke: "
chal3_prompt: "Challenge 3 - Almost there! But can you predict the future?\nWhat number am I thinking of? "