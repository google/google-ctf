bits 64
                org     0x400000

  ehdr:                                                 ; Elf64_Ehdr
                db      0x7F, "ELF", 2, 1, 1, 0         ;   e_ident
        times 8 db      0
                dw      2                               ;   e_type
                dw      0x3e                            ;   e_machine
                dd      1                               ;   e_version
                dq      _start                          ;   e_entry
                dq      phdr - $$                       ;   e_phoff
                dq      0                               ;   e_shoff
                dd      0                               ;   e_flags
                dw      ehdrsize                        ;   e_ehsize
                dw      phdrsize                        ;   e_phentsize
                dw      1                               ;   e_phnum
                dw      0                               ;   e_shentsize
                dw      0                               ;   e_shnum
                dw      0                               ;   e_shstrndx

  ehdrsize      equ     $ - ehdr

  phdr:                                                 ; Elf64_Phdr
                dd      1                               ;   p_type
                dd      7                               ;   p_flags
                dq      0                               ;   p_offset
                dq      $$                              ;   p_vaddr
                dq      $$                              ;   p_paddr
                dq      filesize                        ;   p_filesz
                dq      filesize                        ;   p_memsz
                dq      0x1000                          ;   p_align
  phdrsize      equ     $ - phdr



align 32, db 0
const_0: dq 0, 0, 0, 0
const_1: dq 1, 1, 1, 1
const_2: dq 2, 2, 2, 2
const_3: dq 3, 3, 3, 3
const_4: dq 4, 4, 4, 4
const_8: dq 8, 8, 8, 8
const_12: dq 12, 12, 12, 12
const_16: dq 16, 16, 16, 16
const_20: dq 20, 20, 20, 20
const_24: dq 24, 24, 24, 24
const_28: dq 28, 28, 28, 28
const_32: dq 32, 32, 32, 32
const_36: dq 36, 36, 36, 36
const_40: dq 40, 40, 40, 40
const_44: dq 44, 44, 44, 44
const_48: dq 48, 48, 48, 48
const_52: dq 52, 52, 52, 52
const_56: dq 56, 56, 56, 56
const_60: dq 60, 60, 60, 60
const_64: dq 64, 64, 64, 64
const_68: dq 68, 68, 68, 68
const_72: dq 72, 72, 72, 72
const_252: dq 252, 252, 252, 252
const_255: dq 255, 255, 255, 255

const_m1: dq -1, -1, -1, -1
const_m8: dq -8, -8, -8, -8
const_step1: dq 0, 1, 2, 3

shufb_constant:
    db 0, 128, 8, 128, 128, 128, 128, 128
    db 128, 128, 128, 128, 128, 128, 128, 128
    db 0, 128, 8, 128, 128, 128, 128, 128
    db 128, 128, 128, 128, 128, 128, 128, 128

%assign i 0
%macro def_instruction 1
    %xdefine %1 const_%[i]
    %assign i (i+4)
%endmacro

def_instruction READ_BYTE
def_instruction WRITE_BYTE
def_instruction CPUID
def_instruction GET_PC
def_instruction ADD
def_instruction SUBL
def_instruction SUBR
def_instruction MUL
def_instruction AND
def_instruction OR
def_instruction XOR
def_instruction NOT
def_instruction GET
def_instruction PUT
def_instruction GET_MEM
def_instruction PUT_MEM
def_instruction CONST
def_instruction JMP
def_instruction JNZ

%define pc ymm0
%define acc ymm1
%define reg0 ymm2
%define reg1 ymm3
%define reg2 ymm4
%define reg3 ymm5
%define instruction_full ymm6
%define instruction ymm7
%define register ymm8
%define registervalue ymm9
%define mask ymm10
%define tmp1 ymm11
%define tmp2 ymm12
%define tmp2_small xmm12

syscall_arg: dq 0, 0, 0, 0
mem_helper1: dq 0, 0, 0, 0
mem_helper2: dq 0, 0, 0, 0

_start:
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    xor rbp, rbp
    xor rsp, rsp
    xor rsi, rsi
    xor rdi, rdi
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15
    xor rsp, rsp
    vzeroall

%define SYS_read 0
%define SYS_write 1
%define SYS_exit 60

myloop:
    ;; Fetch the instruction
    vmovdqa mask, [const_m1]
    vpgatherqq instruction_full, [memory + pc], mask
    vpaddq pc, [const_1]

    ;; Split the register and instruction
    vpand instruction, instruction_full, [const_252]
    vpand register, instruction_full, [const_3]
    vpand instruction_full, [const_255]

    ;; Get the register value
    vmovdqa registervalue, reg0
    vpcmpeqq mask, register, [const_1]
    vpblendvb registervalue, registervalue, reg1, mask
    vpcmpeqq mask, register, [const_2]
    vpblendvb registervalue, registervalue, reg2, mask
    vpcmpeqq mask, register, [const_3]
    vpblendvb registervalue, registervalue, reg3, mask

    ;; READ_BYTE
    vpcmpeqq mask, instruction, [READ_BYTE]

    ;; rbp = rdx = (mask ? 1 : 0)
    vpmovmskb rdx, mask
    test rdx, rdx
    mov rdx, 1
    cmovz rdx, [const_0]
    mov rbp, rdx

    ;; read(0, syscall_arg, mask ? 1 : 0)
    mov rax, SYS_read
    mov rdi, 0
    mov rsi, syscall_arg
    syscall

    ;; rax = (read_bytes == expected_read_bytes) ? syscall_arg : 0
    cmp rax, rbp
    mov rax, syscall_arg
    cmovne rax, [const_0]

    vpbroadcastq tmp1, [rax]
    vpblendvb acc, acc, tmp1, mask

    xor rax, rax
    xor rdi, rdi
    xor rsi, rsi
    xor rdx, rdx
    xor rbp, rbp
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11

    ;; WRITE_BYTE
    vpcmpeqq mask, instruction, [WRITE_BYTE]
    vpand tmp1, acc, mask
    vpshufb tmp1, [shufb_constant]
    vphaddsw tmp1, tmp1
    vextracti128 tmp2_small, tmp1, 1
    vpaddd tmp1, tmp2
    vmovdqa [syscall_arg], tmp1

    ;; rdx = (mask ? 1 : 0)
    vpmovmskb rdx, mask
    test rdx, rdx
    mov rdx, 1
    cmovz rdx, [const_0]

    ;; write(1, syscall_arg, mask ? 1 : 0)
    mov rax, SYS_write
    mov rdi, 1
    mov rsi, syscall_arg
    syscall

    xor rax, rax
    xor rdi, rdi
    xor rsi, rsi
    xor rdx, rdx
    xor rbp, rbp
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11

    ;; CPUID
    vpcmpeqq mask, instruction, [CPUID]
    vpblendvb acc, acc, [const_step1], mask

    ;; GET_PC
    vpcmpeqq mask, instruction, [GET_PC]
    vpblendvb acc, acc, pc, mask

    ;; ADD
    vpcmpeqq mask, instruction, [ADD]
    vpaddq tmp1, acc, registervalue
    vpblendvb acc, acc, tmp1, mask

    ;; SUBL
    vpcmpeqq mask, instruction, [SUBL]
    vpsubq tmp1, acc, registervalue
    vpblendvb acc, acc, tmp1, mask

    ;; SUBR
    vpcmpeqq mask, instruction, [SUBR]
    vpsubq tmp1, registervalue, acc
    vpblendvb acc, acc, tmp1, mask

    ;; MUL
    vpcmpeqq mask, instruction, [MUL]
    vpmuludq tmp1, acc, registervalue
    vpblendvb acc, acc, tmp1, mask

    ;; AND
    vpcmpeqq mask, instruction, [AND]
    vpand tmp1, acc, registervalue
    vpblendvb acc, acc, tmp1, mask

    ;; OR
    vpcmpeqq mask, instruction, [OR]
    vpor tmp1, acc, registervalue
    vpblendvb acc, acc, tmp1, mask

    ;; XOR
    vpcmpeqq mask, instruction, [XOR]
    vpxor tmp1, acc, registervalue
    vpblendvb acc, acc, tmp1, mask

    ;; NOT
    vpcmpeqq mask, instruction, [NOT]
    vpcmpeqq tmp1, acc, [const_0]
    vpblendvb acc, acc, tmp1, mask

    ;; GET
    vpcmpeqq mask, instruction, [GET]
    vpblendvb acc, acc, registervalue, mask

    ;; PUT
    vpcmpeqq mask, instruction, [PUT]
    vpcmpeqq tmp1, register, [const_0]
    vpand tmp1, tmp1, mask
    vpblendvb reg0, reg0, acc, tmp1
    vpcmpeqq tmp1, register, [const_1]
    vpand tmp1, tmp1, mask
    vpblendvb reg1, reg1, acc, tmp1
    vpcmpeqq tmp1, register, [const_2]
    vpand tmp1, tmp1, mask
    vpblendvb reg2, reg2, acc, tmp1
    vpcmpeqq tmp1, register, [const_3]
    vpand tmp1, tmp1, mask
    vpblendvb reg3, reg3, acc, tmp1

    ;; GET_MEM
    vpcmpeqq mask, instruction, [GET_MEM]
    vmovdqa tmp1, mask
    vpgatherqq tmp2, [memory + registervalue], tmp1
    vpblendvb acc, acc, tmp2, mask

    ;; PUT_MEM
    vpcmpeqq mask, instruction, [PUT_MEM]
    vmovdqa tmp1, [const_m8]
    vpblendvb tmp1, tmp1, registervalue, mask
    vmovdqa [mem_helper1], tmp1
    vmovdqa [mem_helper2], acc

    mov rax, [mem_helper1 + 0]
    mov rbx, [mem_helper2 + 0]
    mov [memory + rax], rbx

    mov rax, [mem_helper1 + 8]
    mov rbx, [mem_helper2 + 8]
    mov [memory + rax], rbx

    mov rax, [mem_helper1 + 16]
    mov rbx, [mem_helper2 + 16]
    mov [memory + rax], rbx

    mov rax, [mem_helper1 + 24]
    mov rbx, [mem_helper2 + 24]
    mov [memory + rax], rbx

    xor rax, rax
    xor rbx, rbx

    ;; CONST
    vpcmpeqq mask, instruction, [CONST]
    vpand tmp1, mask, [const_8]
    vpgatherqq acc, [memory + pc], mask
    vpaddq pc, tmp1

    ;; JMP
    vpcmpeqq mask, instruction, [JMP]
    vpblendvb pc, pc, acc, mask

    ;; JNZ
    vpcmpeqq mask, instruction, [JNZ]
    vpand mask, mask, registervalue
    vpcmpeqq mask, mask, [const_0]
    vpblendvb pc, acc, pc, mask

    ;; Again!
    jmp myloop

;;; The exact position of memory_helper doesn't matter, since it isn't used
;;; anywhere. We just need at least one ymm-sized value of non-used memory for
;;; the ugly hack done in PUT_MEM
align 32, db 0
memory_helper: dq 0, 0, 0, 0

memory:
    incbin "vm-code.bin"
    filesize      equ     $ - $$
