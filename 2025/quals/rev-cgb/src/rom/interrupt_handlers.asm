; This section defines all the interrupt handlers.
; I was going to give this some use but ended up not using them.
SECTION "VBlank Interrupt", ROM0[$40]
    call    FixedUpdate
    reti
