	.file	"loader.c"
	.intel_syntax noprefix
	.text
#APP
	                                
  .globl syscall1                      
  .type syscall1, @function            
  syscall1:                            
    mov %eax, %edi                     
    mov %rdi, %rsi                     
    syscall                            
    ret                                

	                                
  .globl syscall0                      
  .type syscall0, @function            
  syscall0:                            
    mov %eax, %edi                     
    syscall                            
    ret                                

#NO_APP
	.globl	_start
	.type	_start, @function
_start:
.LFB0:
	.cfi_startproc
	endbr64
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
	.cfi_def_cfa_register 6
	mov	esi, 35
	mov	edi, 60
	call	syscall1@PLT
	.cfi_endproc
.LFE0:
	.size	_start, .-_start
	.ident	"GCC: (Ubuntu 11.2.0-19ubuntu1) 11.2.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
