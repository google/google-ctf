bits 64

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

db OP_AND | A_R | B_R, 0, 00, 0, 00 ; W@0: AND(A_R@0, B_R@0)
