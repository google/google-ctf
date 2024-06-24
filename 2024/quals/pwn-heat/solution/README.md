# HEAT Solution

## TL;DR
Sandbox bypass with wasm dispatch table signature confusion. 

This is a v8 sandbox escape challenge. Players are given a patch and a version of d8 reverted to a commit that was 10 days ago as of the time of gctf 2024. The commit links to a test-case where the wasm dispatch table can be confused to execute "function A" in place of where it was expecting "function B" during a `call_indirect` instruction. 

The provided commit gives a regression test that gives enough context for the full solve. Players can then modify that original test case: you must corrupt the table's type and confuse it by putting a new function into it, then leak the jump table's address with arb read, then write shellcode to the jump table with arb write, and call your function that you injected into the dispatch table.

I am also aware of a few unintended cheese solutions which, ah c'est la vie. I also know that any v8ctf members can throw any of their 1 and 0 days at it too. I encourage all who looked at this challenge to participate in v8ctf and contribute to the security of future v8 sandboxes in the future :>