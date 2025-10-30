bits 16

%define M_T 0x80
%define M_N 0x00
%define OP_X 0x40
%define OP_N 0x20
%define OP_AND 0x00
%define OP_OR 0x10
%define OP_XOR OP_X | OP_OR
%define OP_NOR OP_N | OP_OR
%define OP_XNOR OP_X | OP_N | OP_OR
%define OP_NAND OP_N | OP_AND
%define A_DATA 0x08
%define A_PROG 0x00
%define B_DATA 0x02
%define B_PROG 0x00
%define A_W A_PROG | 0x00
%define A_B A_PROG | 0x04
%define A_D A_DATA | 0x00
%define A_R A_DATA | 0x04
%define B_W B_PROG | 0x00
%define B_B B_PROG | 0x01
%define B_D B_DATA | 0x00
%define B_R B_DATA | 0x01

%macro $_AND_ 4
db M_T | OP_AND | A_%1 | B_%3
dw %2
dw %4
%endmacro

%macro $_NAND_ 4
db M_T | OP_NAND | A_%1 | B_%3
dw %2
dw %4
%endmacro

%macro $_OR_ 4
db M_T | OP_OR | A_%1 | B_%3
dw %2
dw %4
%endmacro

%macro $_XOR_ 4
db M_T | OP_XOR | A_%1 | B_%3
dw %2
dw %4
%endmacro

%macro $_NOR_ 4
db M_T | OP_NOR | A_%1 | B_%3
dw %2
dw %4
%endmacro

%macro $_XNOR_ 4
db M_T | OP_XNOR | A_%1 | B_%3
dw %2
dw %4
%endmacro

%macro $_NOT_ 2
$_XOR_ %1, %2, B, 7
%endmacro

%macro $_REF_ 1
$_AND_ W, %1, B, 7
%endmacro

%macro $_ZERO_ 0
$_XOR_ B, 7, B, 7
%endmacro
