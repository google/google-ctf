MEMORY
{
    ROM (rx) : ORIGIN = 0, LENGTH = 0x400000
    RAM (rwx) : ORIGIN = 0xFF0000, LENGTH = 0x10000
}

ENTRY(_start)

SECTIONS
{
    _stack_top = 0x1000000;
    _stack_bottom = _stack_top - 0x500;

    .text :
    {
        *(.text .text.*);
    } > ROM

    .rodata :
    {
        . = ALIGN(4);
        *(.rodata .rodata.*);
    } > ROM

    .data : AT(ADDR(.rodata) + SIZEOF(.rodata))
    {
        . = ALIGN(4);
        _data_start = .;
        *(.data);
        _data_end = .;
    } > RAM

    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        _bss_start = .;
        *(.bss .bss.*);
        _bss_end = .;
    } > RAM

    _data_src = LOADADDR(.data);

    _heap_start = 0xFF0100;
    _heap_end   = _stack_bottom;
    /* Flag ID stored at fixed offset for server-side verification */
    GOT_FLAG = 0xFF0000;

    /*/DISCARD/ : */
}
