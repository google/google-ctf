;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.0.0 #11528 (Linux)
;--------------------------------------------------------
	.module firmware
	.optsdcc -mmcs51 --model-small
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _tokenizer_init_PARM_2
	.globl _i2c_read_PARM_3
	.globl _i2c_read_PARM_2
	.globl _i2c_write_PARM_3
	.globl _i2c_write_PARM_2
	.globl _main
	.globl _port_to_int8
	.globl _is_port_allowed
	.globl _uint8_to_str
	.globl _str_to_uint8
	.globl _tokenizer_next
	.globl _tokenizer_init
	.globl _serial_read_char
	.globl _serial_print
	.globl _i2c_status_to_error
	.globl _i2c_read
	.globl _i2c_write
	.globl _POWERSAVE
	.globl _POWEROFF
	.globl _I2C_READ_WRITE
	.globl _I2C_ADDRESS
	.globl _I2C_BUFFER_SIZE
	.globl _I2C_BUFFER_XRAM_HIGH
	.globl _I2C_BUFFER_XRAM_LOW
	.globl _I2C_STATUS
	.globl _SERIAL_IN_READY
	.globl _SERIAL_IN_DATA
	.globl _SERIAL_OUT_READY
	.globl _SERIAL_OUT_DATA
	.globl _FLAGROM_DATA
	.globl _FLAGROM_ADDR
	.globl _uint8_to_str_PARM_2
	.globl _ALLOWED_I2C
;--------------------------------------------------------
; special function registers
;--------------------------------------------------------
	.area RSEG    (ABS,DATA)
	.org 0x0000
_FLAGROM_ADDR	=	0x00ee
_FLAGROM_DATA	=	0x00ef
_SERIAL_OUT_DATA	=	0x00f2
_SERIAL_OUT_READY	=	0x00f3
_SERIAL_IN_DATA	=	0x00fa
_SERIAL_IN_READY	=	0x00fb
_I2C_STATUS	=	0x00e1
_I2C_BUFFER_XRAM_LOW	=	0x00e2
_I2C_BUFFER_XRAM_HIGH	=	0x00e3
_I2C_BUFFER_SIZE	=	0x00e4
_I2C_ADDRESS	=	0x00e6
_I2C_READ_WRITE	=	0x00e7
_POWEROFF	=	0x00ff
_POWERSAVE	=	0x00fe
;--------------------------------------------------------
; special function bits
;--------------------------------------------------------
	.area RSEG    (ABS,DATA)
	.org 0x0000
;--------------------------------------------------------
; overlayable register banks
;--------------------------------------------------------
	.area REG_BANK_0	(REL,OVR,DATA)
	.ds 8
;--------------------------------------------------------
; internal ram data
;--------------------------------------------------------
	.area DSEG    (DATA)
_ALLOWED_I2C::
	.ds 18
_uint8_to_str_PARM_2:
	.ds 1
_main_t_131075_60:
	.ds 5
_main_num_327687_80:
	.ds 4
;--------------------------------------------------------
; overlayable items in internal ram 
;--------------------------------------------------------
	.area	OSEG    (OVR,DATA)
_i2c_write_PARM_2:
	.ds 1
_i2c_write_PARM_3:
	.ds 2
	.area	OSEG    (OVR,DATA)
_i2c_read_PARM_2:
	.ds 1
_i2c_read_PARM_3:
	.ds 2
	.area	OSEG    (OVR,DATA)
	.area	OSEG    (OVR,DATA)
	.area	OSEG    (OVR,DATA)
_tokenizer_init_PARM_2:
	.ds 3
	.area	OSEG    (OVR,DATA)
_tokenizer_next_t_65536_24:
	.ds 3
_tokenizer_next_token_start_65537_29:
	.ds 3
	.area	OSEG    (OVR,DATA)
	.area	OSEG    (OVR,DATA)
_is_port_allowed_port_65536_41:
	.ds 3
_is_port_allowed_pa_196608_44:
	.ds 3
_is_port_allowed_pb_196608_44:
	.ds 3
_is_port_allowed_sloc0_1_0:
	.ds 3
_is_port_allowed_sloc1_1_0:
	.ds 1
;--------------------------------------------------------
; Stack segment in internal ram 
;--------------------------------------------------------
	.area	SSEG
__start__stack:
	.ds	1

;--------------------------------------------------------
; indirectly addressable internal ram data
;--------------------------------------------------------
	.area ISEG    (DATA)
;--------------------------------------------------------
; absolute internal ram data
;--------------------------------------------------------
	.area IABS    (ABS,DATA)
	.area IABS    (ABS,DATA)
;--------------------------------------------------------
; bit data
;--------------------------------------------------------
	.area BSEG    (BIT)
;--------------------------------------------------------
; paged external ram data
;--------------------------------------------------------
	.area PSEG    (PAG,XDATA)
;--------------------------------------------------------
; external ram data
;--------------------------------------------------------
	.area XSEG    (XDATA)
_main_cmd_65537_53:
	.ds 384
_main_i2c_buf_65537_53:
	.ds 128
;--------------------------------------------------------
; absolute external ram data
;--------------------------------------------------------
	.area XABS    (ABS,XDATA)
;--------------------------------------------------------
; external initialized ram data
;--------------------------------------------------------
	.area XISEG   (XDATA)
	.area HOME    (CODE)
	.area GSINIT0 (CODE)
	.area GSINIT1 (CODE)
	.area GSINIT2 (CODE)
	.area GSINIT3 (CODE)
	.area GSINIT4 (CODE)
	.area GSINIT5 (CODE)
	.area GSINIT  (CODE)
	.area GSFINAL (CODE)
	.area CSEG    (CODE)
;--------------------------------------------------------
; interrupt vector 
;--------------------------------------------------------
	.area HOME    (CODE)
__interrupt_vect:
	ljmp	__sdcc_gsinit_startup
;--------------------------------------------------------
; global & static initialisations
;--------------------------------------------------------
	.area HOME    (CODE)
	.area GSINIT  (CODE)
	.area GSFINAL (CODE)
	.area GSINIT  (CODE)
	.globl __sdcc_gsinit_startup
	.globl __sdcc_program_startup
	.globl __start__stack
	.globl __mcs51_genXINIT
	.globl __mcs51_genXRAMCLEAR
	.globl __mcs51_genRAMCLEAR
;	firmware.c:30: const char *ALLOWED_I2C[] = {
	mov	(_ALLOWED_I2C + 0),#___str_15
	mov	(_ALLOWED_I2C + 1),#(___str_15 >> 8)
	mov	(_ALLOWED_I2C + 2),#0x80
	mov	((_ALLOWED_I2C + 0x0003) + 0),#___str_16
	mov	((_ALLOWED_I2C + 0x0003) + 1),#(___str_16 >> 8)
	mov	((_ALLOWED_I2C + 0x0003) + 2),#0x80
	mov	((_ALLOWED_I2C + 0x0006) + 0),#___str_17
	mov	((_ALLOWED_I2C + 0x0006) + 1),#(___str_17 >> 8)
	mov	((_ALLOWED_I2C + 0x0006) + 2),#0x80
	mov	((_ALLOWED_I2C + 0x0009) + 0),#___str_18
	mov	((_ALLOWED_I2C + 0x0009) + 1),#(___str_18 >> 8)
	mov	((_ALLOWED_I2C + 0x0009) + 2),#0x80
	mov	((_ALLOWED_I2C + 0x000c) + 0),#___str_19
	mov	((_ALLOWED_I2C + 0x000c) + 1),#(___str_19 >> 8)
	mov	((_ALLOWED_I2C + 0x000c) + 2),#0x80
	clr	a
	mov	((_ALLOWED_I2C + 0x000f) + 0),a
	mov	((_ALLOWED_I2C + 0x000f) + 1),a
	mov	((_ALLOWED_I2C + 0x000f) + 2),a
	.area GSFINAL (CODE)
	ljmp	__sdcc_program_startup
;--------------------------------------------------------
; Home
;--------------------------------------------------------
	.area HOME    (CODE)
	.area HOME    (CODE)
__sdcc_program_startup:
	ljmp	_main
;	return from main will return to caller
;--------------------------------------------------------
; code
;--------------------------------------------------------
	.area CSEG    (CODE)
;------------------------------------------------------------
;Allocation info for local variables in function 'i2c_write'
;------------------------------------------------------------
;req_len                   Allocated with name '_i2c_write_PARM_2'
;buf                       Allocated with name '_i2c_write_PARM_3'
;port                      Allocated to registers r7 
;status                    Allocated to registers r7 
;------------------------------------------------------------
;	firmware.c:39: int8_t i2c_write(int8_t port, uint8_t req_len, __xdata uint8_t *buf) {
;	-----------------------------------------
;	 function i2c_write
;	-----------------------------------------
_i2c_write:
	ar7 = 0x07
	ar6 = 0x06
	ar5 = 0x05
	ar4 = 0x04
	ar3 = 0x03
	ar2 = 0x02
	ar1 = 0x01
	ar0 = 0x00
	mov	r7,dpl
;	firmware.c:40: while (I2C_STATUS == 1) {
00101$:
	mov	a,#0x01
	cjne	a,_I2C_STATUS,00103$
;	firmware.c:41: POWERSAVE = 1;  // Enter power save mode for a few milliseconds.
	mov	_POWERSAVE,#0x01
	sjmp	00101$
00103$:
;	firmware.c:44: I2C_BUFFER_XRAM_LOW = (uint8_t)(uint16_t)buf;
	mov	_I2C_BUFFER_XRAM_LOW,_i2c_write_PARM_3
;	firmware.c:45: I2C_BUFFER_XRAM_HIGH = (uint8_t)((uint16_t)buf >> 8);
	mov	r6,(_i2c_write_PARM_3 + 1)
	mov	_I2C_BUFFER_XRAM_HIGH,r6
;	firmware.c:46: I2C_BUFFER_SIZE = req_len;
	mov	_I2C_BUFFER_SIZE,_i2c_write_PARM_2
;	firmware.c:47: I2C_ADDRESS = port;
	mov	_I2C_ADDRESS,r7
;	firmware.c:49: I2C_READ_WRITE = 0;  // Start write.
	mov	_I2C_READ_WRITE,#0x00
;	firmware.c:52: while ((status = I2C_STATUS) == 1) {
00104$:
	mov	r7,_I2C_STATUS
	mov	a,#0x01
	cjne	a,_I2C_STATUS,00106$
;	firmware.c:53: POWERSAVE = 1;  // Enter power save mode for a few milliseconds.
	mov	_POWERSAVE,#0x01
	sjmp	00104$
00106$:
;	firmware.c:56: return status;
	mov	dpl,r7
;	firmware.c:57: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'i2c_read'
;------------------------------------------------------------
;req_len                   Allocated with name '_i2c_read_PARM_2'
;buf                       Allocated with name '_i2c_read_PARM_3'
;port                      Allocated to registers r7 
;status                    Allocated to registers r7 
;------------------------------------------------------------
;	firmware.c:59: int8_t i2c_read(int8_t port, uint8_t req_len, __xdata uint8_t *buf) {
;	-----------------------------------------
;	 function i2c_read
;	-----------------------------------------
_i2c_read:
	mov	r7,dpl
;	firmware.c:60: while (I2C_STATUS == 1) {
00101$:
	mov	a,#0x01
	cjne	a,_I2C_STATUS,00103$
;	firmware.c:61: POWERSAVE = 1;  // Enter power save mode for a few milliseconds.
	mov	_POWERSAVE,#0x01
	sjmp	00101$
00103$:
;	firmware.c:64: I2C_BUFFER_XRAM_LOW = (uint8_t)(uint16_t)buf;
	mov	_I2C_BUFFER_XRAM_LOW,_i2c_read_PARM_3
;	firmware.c:65: I2C_BUFFER_XRAM_HIGH = (uint8_t)((uint16_t)buf >> 8);
	mov	r6,(_i2c_read_PARM_3 + 1)
	mov	_I2C_BUFFER_XRAM_HIGH,r6
;	firmware.c:66: I2C_BUFFER_SIZE = req_len;
	mov	_I2C_BUFFER_SIZE,_i2c_read_PARM_2
;	firmware.c:67: I2C_ADDRESS = port;
	mov	_I2C_ADDRESS,r7
;	firmware.c:69: I2C_READ_WRITE = 1;  // Start read.
	mov	_I2C_READ_WRITE,#0x01
;	firmware.c:72: while ((status = I2C_STATUS) == 1) {
00104$:
	mov	r7,_I2C_STATUS
	mov	a,#0x01
	cjne	a,_I2C_STATUS,00106$
;	firmware.c:73: POWERSAVE = 1;  // Enter power save mode for a few milliseconds.
	mov	_POWERSAVE,#0x01
	sjmp	00104$
00106$:
;	firmware.c:76: return status;
	mov	dpl,r7
;	firmware.c:77: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'i2c_status_to_error'
;------------------------------------------------------------
;err                       Allocated to registers r7 
;------------------------------------------------------------
;	firmware.c:79: const char *i2c_status_to_error(int8_t err) {
;	-----------------------------------------
;	 function i2c_status_to_error
;	-----------------------------------------
_i2c_status_to_error:
	mov	r7,dpl
;	firmware.c:80: switch (err) {
	cjne	r7,#0x00,00124$
	sjmp	00101$
00124$:
	cjne	r7,#0x01,00125$
	sjmp	00102$
00125$:
	cjne	r7,#0x02,00126$
	sjmp	00103$
00126$:
;	firmware.c:81: case 0: return "i2c status: transaction completed / ready\n";
	cjne	r7,#0x03,00105$
	sjmp	00104$
00101$:
	mov	dptr,#___str_0
	mov	b,#0x80
;	firmware.c:82: case 1: return "i2c status: busy\n";
	ret
00102$:
	mov	dptr,#___str_1
	mov	b,#0x80
;	firmware.c:83: case 2: return "i2c status: error - device not found\n";
	ret
00103$:
	mov	dptr,#___str_2
	mov	b,#0x80
;	firmware.c:84: case 3: return "i2c status: error - device misbehaved\n";
	ret
00104$:
	mov	dptr,#___str_3
	mov	b,#0x80
;	firmware.c:85: }
	ret
00105$:
;	firmware.c:87: return "i2c status: unknown error\n";
	mov	dptr,#___str_4
	mov	b,#0x80
;	firmware.c:88: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'serial_print'
;------------------------------------------------------------
;s                         Allocated to registers 
;------------------------------------------------------------
;	firmware.c:90: void serial_print(const char *s) {
;	-----------------------------------------
;	 function serial_print
;	-----------------------------------------
_serial_print:
	mov	r5,dpl
	mov	r6,dph
	mov	r7,b
;	firmware.c:91: while (*s) {
00104$:
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	lcall	__gptrget
	jz	00107$
;	firmware.c:92: while (!SERIAL_OUT_READY) {
00101$:
	mov	a,_SERIAL_OUT_READY
	jz	00101$
;	firmware.c:96: SERIAL_OUT_DATA = *s++;
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	lcall	__gptrget
	mov	_SERIAL_OUT_DATA,a
	inc	dptr
	mov	r5,dpl
	mov	r6,dph
	sjmp	00104$
00107$:
;	firmware.c:98: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'serial_read_char'
;------------------------------------------------------------
;	firmware.c:100: char serial_read_char(void) {
;	-----------------------------------------
;	 function serial_read_char
;	-----------------------------------------
_serial_read_char:
;	firmware.c:101: while (1) {
00104$:
;	firmware.c:102: if (SERIAL_IN_READY) {
	mov	a,_SERIAL_IN_READY
	jz	00102$
;	firmware.c:103: return (char)SERIAL_IN_DATA;
	mov	dpl,_SERIAL_IN_DATA
	ret
00102$:
;	firmware.c:106: POWERSAVE = 1;  // Enter power save mode for a few milliseconds.
	mov	_POWERSAVE,#0x01
;	firmware.c:108: }
	sjmp	00104$
;------------------------------------------------------------
;Allocation info for local variables in function 'tokenizer_init'
;------------------------------------------------------------
;str                       Allocated with name '_tokenizer_init_PARM_2'
;t                         Allocated to registers r5 r6 r7 
;------------------------------------------------------------
;	firmware.c:115: void tokenizer_init(struct tokenizer_st *t, char *str) {
;	-----------------------------------------
;	 function tokenizer_init
;	-----------------------------------------
_tokenizer_init:
;	firmware.c:116: t->ptr = str;
	mov	r5,dpl
	mov	r6,dph
	mov	r7,b
	mov	a,_tokenizer_init_PARM_2
	lcall	__gptrput
	inc	dptr
	mov	a,(_tokenizer_init_PARM_2 + 1)
	lcall	__gptrput
	inc	dptr
	mov	a,(_tokenizer_init_PARM_2 + 2)
	lcall	__gptrput
;	firmware.c:117: t->replaced = 0x7fff;
	mov	a,#0x03
	add	a,r5
	mov	r5,a
	clr	a
	addc	a,r6
	mov	r6,a
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	mov	a,#0xff
	lcall	__gptrput
	inc	dptr
	mov	a,#0x7f
;	firmware.c:118: }
	ljmp	__gptrput
;------------------------------------------------------------
;Allocation info for local variables in function 'tokenizer_next'
;------------------------------------------------------------
;t                         Allocated with name '_tokenizer_next_t_65536_24'
;token_start               Allocated with name '_tokenizer_next_token_start_65537_29'
;ch                        Allocated to registers r7 
;------------------------------------------------------------
;	firmware.c:120: char *tokenizer_next(struct tokenizer_st *t) {
;	-----------------------------------------
;	 function tokenizer_next
;	-----------------------------------------
_tokenizer_next:
	mov	_tokenizer_next_t_65536_24,dpl
	mov	(_tokenizer_next_t_65536_24 + 1),dph
	mov	(_tokenizer_next_t_65536_24 + 2),b
;	firmware.c:121: if (t->replaced != 0x7fff) {
	mov	a,#0x03
	add	a,_tokenizer_next_t_65536_24
	mov	r2,a
	clr	a
	addc	a,(_tokenizer_next_t_65536_24 + 1)
	mov	r3,a
	mov	r4,(_tokenizer_next_t_65536_24 + 2)
	mov	dpl,r2
	mov	dph,r3
	mov	b,r4
	lcall	__gptrget
	mov	r0,a
	inc	dptr
	lcall	__gptrget
	mov	r1,a
	cjne	r0,#0xff,00144$
	cjne	r1,#0x7f,00144$
	sjmp	00103$
00144$:
;	firmware.c:122: *t->ptr = (char)t->replaced;
	mov	dpl,_tokenizer_next_t_65536_24
	mov	dph,(_tokenizer_next_t_65536_24 + 1)
	mov	b,(_tokenizer_next_t_65536_24 + 2)
	lcall	__gptrget
	mov	r5,a
	inc	dptr
	lcall	__gptrget
	mov	r6,a
	inc	dptr
	lcall	__gptrget
	mov	r7,a
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	mov	a,r0
	lcall	__gptrput
;	firmware.c:125: while (*t->ptr == ' ') {
00103$:
	mov	dpl,_tokenizer_next_t_65536_24
	mov	dph,(_tokenizer_next_t_65536_24 + 1)
	mov	b,(_tokenizer_next_t_65536_24 + 2)
	lcall	__gptrget
	mov	r5,a
	inc	dptr
	lcall	__gptrget
	mov	r6,a
	inc	dptr
	lcall	__gptrget
	mov	r7,a
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	lcall	__gptrget
	mov	r5,a
	cjne	r5,#0x20,00105$
;	firmware.c:126: t->ptr++;
	mov	dpl,_tokenizer_next_t_65536_24
	mov	dph,(_tokenizer_next_t_65536_24 + 1)
	mov	b,(_tokenizer_next_t_65536_24 + 2)
	lcall	__gptrget
	mov	r5,a
	inc	dptr
	lcall	__gptrget
	mov	r6,a
	inc	dptr
	lcall	__gptrget
	mov	r7,a
	inc	r5
	cjne	r5,#0x00,00147$
	inc	r6
00147$:
	mov	dpl,_tokenizer_next_t_65536_24
	mov	dph,(_tokenizer_next_t_65536_24 + 1)
	mov	b,(_tokenizer_next_t_65536_24 + 2)
	mov	a,r5
	lcall	__gptrput
	inc	dptr
	mov	a,r6
	lcall	__gptrput
	inc	dptr
	mov	a,r7
	lcall	__gptrput
	sjmp	00103$
00105$:
;	firmware.c:129: if (*t->ptr == '\0') {
	mov	dpl,_tokenizer_next_t_65536_24
	mov	dph,(_tokenizer_next_t_65536_24 + 1)
	mov	b,(_tokenizer_next_t_65536_24 + 2)
	lcall	__gptrget
	mov	r5,a
	inc	dptr
	lcall	__gptrget
	mov	r6,a
	inc	dptr
	lcall	__gptrget
	mov	r7,a
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	lcall	__gptrget
;	firmware.c:130: return NULL;
	jnz	00107$
	mov	dptr,#0x0000
	mov	b,a
	ret
00107$:
;	firmware.c:133: char *token_start = t->ptr;
	mov	dpl,_tokenizer_next_t_65536_24
	mov	dph,(_tokenizer_next_t_65536_24 + 1)
	mov	b,(_tokenizer_next_t_65536_24 + 2)
	lcall	__gptrget
	mov	_tokenizer_next_token_start_65537_29,a
	inc	dptr
	lcall	__gptrget
	mov	(_tokenizer_next_token_start_65537_29 + 1),a
	inc	dptr
	lcall	__gptrget
	mov	(_tokenizer_next_token_start_65537_29 + 2),a
00113$:
;	firmware.c:135: char ch = *t->ptr;
	mov	dpl,_tokenizer_next_t_65536_24
	mov	dph,(_tokenizer_next_t_65536_24 + 1)
	mov	b,(_tokenizer_next_t_65536_24 + 2)
	lcall	__gptrget
	mov	r0,a
	inc	dptr
	lcall	__gptrget
	mov	r1,a
	inc	dptr
	lcall	__gptrget
	mov	r7,a
	mov	dpl,r0
	mov	dph,r1
	mov	b,r7
	lcall	__gptrget
	mov	r7,a
;	firmware.c:136: if (ch != ' ' && ch != '\0') {
	cjne	r7,#0x20,00149$
	sjmp	00109$
00149$:
	mov	a,r7
	jz	00109$
;	firmware.c:137: t->ptr++;
	mov	dpl,_tokenizer_next_t_65536_24
	mov	dph,(_tokenizer_next_t_65536_24 + 1)
	mov	b,(_tokenizer_next_t_65536_24 + 2)
	lcall	__gptrget
	mov	r5,a
	inc	dptr
	lcall	__gptrget
	mov	r6,a
	inc	dptr
	lcall	__gptrget
	mov	r7,a
	inc	r5
	cjne	r5,#0x00,00151$
	inc	r6
00151$:
	mov	dpl,_tokenizer_next_t_65536_24
	mov	dph,(_tokenizer_next_t_65536_24 + 1)
	mov	b,(_tokenizer_next_t_65536_24 + 2)
	mov	a,r5
	lcall	__gptrput
	inc	dptr
	mov	a,r6
	lcall	__gptrput
	inc	dptr
	mov	a,r7
	lcall	__gptrput
;	firmware.c:138: continue;
	sjmp	00113$
00109$:
;	firmware.c:141: t->replaced = *t->ptr;
	mov	dpl,_tokenizer_next_t_65536_24
	mov	dph,(_tokenizer_next_t_65536_24 + 1)
	mov	b,(_tokenizer_next_t_65536_24 + 2)
	lcall	__gptrget
	mov	r5,a
	inc	dptr
	lcall	__gptrget
	mov	r6,a
	inc	dptr
	lcall	__gptrget
	mov	r7,a
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	lcall	__gptrget
	mov	r5,a
	mov	r7,#0x00
	mov	dpl,r2
	mov	dph,r3
	mov	b,r4
	mov	a,r5
	lcall	__gptrput
	inc	dptr
	mov	a,r7
	lcall	__gptrput
;	firmware.c:142: *t->ptr = '\0';
	mov	dpl,_tokenizer_next_t_65536_24
	mov	dph,(_tokenizer_next_t_65536_24 + 1)
	mov	b,(_tokenizer_next_t_65536_24 + 2)
	lcall	__gptrget
	mov	r5,a
	inc	dptr
	lcall	__gptrget
	mov	r6,a
	inc	dptr
	lcall	__gptrget
	mov	r7,a
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	clr	a
	lcall	__gptrput
;	firmware.c:143: return token_start;
	mov	dpl,_tokenizer_next_token_start_65537_29
	mov	dph,(_tokenizer_next_token_start_65537_29 + 1)
	mov	b,(_tokenizer_next_token_start_65537_29 + 2)
;	firmware.c:145: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'str_to_uint8'
;------------------------------------------------------------
;s                         Allocated to registers 
;v                         Allocated to registers r4 
;digit                     Allocated to registers r3 
;------------------------------------------------------------
;	firmware.c:147: uint8_t str_to_uint8(const char *s) {
;	-----------------------------------------
;	 function str_to_uint8
;	-----------------------------------------
_str_to_uint8:
	mov	r5,dpl
	mov	r6,dph
	mov	r7,b
;	firmware.c:148: uint8_t v = 0;
	mov	r4,#0x00
;	firmware.c:149: while (*s) {
00103$:
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	lcall	__gptrget
	mov	r3,a
	jz	00105$
;	firmware.c:150: uint8_t digit = *s++ - '0';
	inc	r5
	cjne	r5,#0x00,00121$
	inc	r6
00121$:
	mov	a,r3
	add	a,#0xd0
	mov	r3,a
;	firmware.c:151: if (digit >= 10) {
	cjne	r3,#0x0a,00122$
00122$:
	jc	00102$
;	firmware.c:152: return 0;
	mov	dpl,#0x00
	ret
00102$:
;	firmware.c:154: v = v * 10 + digit;
	mov	ar2,r4
	mov	a,r2
	mov	b,#0x0a
	mul	ab
	mov	r2,a
	add	a,r3
	mov	r4,a
	sjmp	00103$
00105$:
;	firmware.c:156: return v;
	mov	dpl,r4
;	firmware.c:157: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'uint8_to_str'
;------------------------------------------------------------
;v                         Allocated with name '_uint8_to_str_PARM_2'
;buf                       Allocated to registers r5 r6 r7 
;------------------------------------------------------------
;	firmware.c:159: void uint8_to_str(char *buf, uint8_t v) {
;	-----------------------------------------
;	 function uint8_to_str
;	-----------------------------------------
_uint8_to_str:
	mov	r5,dpl
	mov	r6,dph
	mov	r7,b
;	firmware.c:160: if (v >= 100) {
	mov	a,#0x100 - 0x64
	add	a,_uint8_to_str_PARM_2
	jnc	00102$
;	firmware.c:161: *buf++ = '0' + v / 100;
	mov	r3,_uint8_to_str_PARM_2
	mov	r4,#0x00
	mov	__divsint_PARM_2,#0x64
;	1-genFromRTrack replaced	mov	(__divsint_PARM_2 + 1),#0x00
	mov	(__divsint_PARM_2 + 1),r4
	mov	dpl,r3
	mov	dph,r4
	push	ar7
	push	ar6
	push	ar5
	lcall	__divsint
	mov	r3,dpl
	mov	r4,dph
	pop	ar5
	pop	ar6
	pop	ar7
	mov	a,#0x30
	add	a,r3
	mov	r3,a
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	lcall	__gptrput
	inc	dptr
	mov	r5,dpl
	mov	r6,dph
00102$:
;	firmware.c:164: if (v >= 10) {
	mov	a,#0x100 - 0x0a
	add	a,_uint8_to_str_PARM_2
	jnc	00104$
;	firmware.c:165: *buf++ = '0' + (v / 10) % 10;
	mov	r3,_uint8_to_str_PARM_2
	mov	r4,#0x00
	mov	__divsint_PARM_2,#0x0a
;	1-genFromRTrack replaced	mov	(__divsint_PARM_2 + 1),#0x00
	mov	(__divsint_PARM_2 + 1),r4
	mov	dpl,r3
	mov	dph,r4
	push	ar7
	push	ar6
	push	ar5
	lcall	__divsint
	mov	__modsint_PARM_2,#0x0a
	mov	(__modsint_PARM_2 + 1),#0x00
	lcall	__modsint
	mov	r3,dpl
	mov	r4,dph
	pop	ar5
	pop	ar6
	pop	ar7
	mov	a,#0x30
	add	a,r3
	mov	r3,a
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	lcall	__gptrput
	inc	dptr
	mov	r5,dpl
	mov	r6,dph
00104$:
;	firmware.c:168: *buf++ = '0' + v % 10;
	mov	r3,_uint8_to_str_PARM_2
	mov	r4,#0x00
	mov	__modsint_PARM_2,#0x0a
;	1-genFromRTrack replaced	mov	(__modsint_PARM_2 + 1),#0x00
	mov	(__modsint_PARM_2 + 1),r4
	mov	dpl,r3
	mov	dph,r4
	push	ar7
	push	ar6
	push	ar5
	lcall	__modsint
	mov	r3,dpl
	pop	ar5
	pop	ar6
	pop	ar7
	mov	a,#0x30
	add	a,r3
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	lcall	__gptrput
	inc	r5
	cjne	r5,#0x00,00119$
	inc	r6
00119$:
;	firmware.c:169: *buf = '\0';
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	clr	a
;	firmware.c:170: }
	ljmp	__gptrput
;------------------------------------------------------------
;Allocation info for local variables in function 'is_port_allowed'
;------------------------------------------------------------
;port                      Allocated with name '_is_port_allowed_port_65536_41'
;allowed                   Allocated to registers 
;pa                        Allocated with name '_is_port_allowed_pa_196608_44'
;pb                        Allocated with name '_is_port_allowed_pb_196608_44'
;allowed                   Allocated to registers r6 
;sloc0                     Allocated with name '_is_port_allowed_sloc0_1_0'
;sloc1                     Allocated with name '_is_port_allowed_sloc1_1_0'
;------------------------------------------------------------
;	firmware.c:172: bool is_port_allowed(const char *port) {
;	-----------------------------------------
;	 function is_port_allowed
;	-----------------------------------------
_is_port_allowed:
	mov	_is_port_allowed_port_65536_41,dpl
	mov	(_is_port_allowed_port_65536_41 + 1),dph
	mov	(_is_port_allowed_port_65536_41 + 2),b
;	firmware.c:173: for(const char **allowed = ALLOWED_I2C; *allowed; allowed++) {
	mov	r2,#_ALLOWED_I2C
	mov	r3,#0x00
	mov	r4,#0x40
00112$:
	mov	dpl,r2
	mov	dph,r3
	mov	b,r4
	lcall	__gptrget
	mov	_is_port_allowed_sloc0_1_0,a
	inc	dptr
	lcall	__gptrget
	mov	(_is_port_allowed_sloc0_1_0 + 1),a
	inc	dptr
	lcall	__gptrget
	mov	(_is_port_allowed_sloc0_1_0 + 2),a
	mov	a,_is_port_allowed_sloc0_1_0
	orl	a,(_is_port_allowed_sloc0_1_0 + 1)
	jnz	00148$
	ljmp	00110$
00148$:
;	firmware.c:174: const char *pa = *allowed;
;	firmware.c:176: bool allowed = true;
;	firmware.c:177: while (*pa && *pb) {
	mov	_is_port_allowed_pa_196608_44,_is_port_allowed_sloc0_1_0
	mov	(_is_port_allowed_pa_196608_44 + 1),(_is_port_allowed_sloc0_1_0 + 1)
	mov	(_is_port_allowed_pa_196608_44 + 2),(_is_port_allowed_sloc0_1_0 + 2)
	mov	r6,#0x01
	mov	_is_port_allowed_pb_196608_44,_is_port_allowed_port_65536_41
	mov	(_is_port_allowed_pb_196608_44 + 1),(_is_port_allowed_port_65536_41 + 1)
	mov	(_is_port_allowed_pb_196608_44 + 2),(_is_port_allowed_port_65536_41 + 2)
00104$:
	mov	dpl,_is_port_allowed_sloc0_1_0
	mov	dph,(_is_port_allowed_sloc0_1_0 + 1)
	mov	b,(_is_port_allowed_sloc0_1_0 + 2)
	lcall	__gptrget
	mov	r0,a
	jz	00106$
	mov	dpl,_is_port_allowed_pb_196608_44
	mov	dph,(_is_port_allowed_pb_196608_44 + 1)
	mov	b,(_is_port_allowed_pb_196608_44 + 2)
	lcall	__gptrget
	mov	_is_port_allowed_sloc1_1_0,a
	jz	00106$
;	firmware.c:178: if (*pa++ != *pb++) {
	inc	_is_port_allowed_sloc0_1_0
	clr	a
	cjne	a,_is_port_allowed_sloc0_1_0,00151$
	inc	(_is_port_allowed_sloc0_1_0 + 1)
00151$:
	mov	_is_port_allowed_pa_196608_44,_is_port_allowed_sloc0_1_0
	mov	(_is_port_allowed_pa_196608_44 + 1),(_is_port_allowed_sloc0_1_0 + 1)
	mov	(_is_port_allowed_pa_196608_44 + 2),(_is_port_allowed_sloc0_1_0 + 2)
	mov	r7,_is_port_allowed_sloc1_1_0
	inc	_is_port_allowed_pb_196608_44
	clr	a
	cjne	a,_is_port_allowed_pb_196608_44,00152$
	inc	(_is_port_allowed_pb_196608_44 + 1)
00152$:
	mov	a,r0
	cjne	a,ar7,00153$
	sjmp	00104$
00153$:
;	firmware.c:179: allowed = false;
	mov	r6,#0x00
;	firmware.c:180: break;
00106$:
;	firmware.c:183: if (allowed && *pa == '\0') {
	mov	a,r6
	jz	00113$
	mov	dpl,_is_port_allowed_pa_196608_44
	mov	dph,(_is_port_allowed_pa_196608_44 + 1)
	mov	b,(_is_port_allowed_pa_196608_44 + 2)
	lcall	__gptrget
	jnz	00113$
;	firmware.c:184: return true;
	mov	dpl,#0x01
	ret
00113$:
;	firmware.c:173: for(const char **allowed = ALLOWED_I2C; *allowed; allowed++) {
	mov	a,#0x03
	add	a,r2
	mov	r2,a
	clr	a
	addc	a,r3
	mov	r3,a
	ljmp	00112$
00110$:
;	firmware.c:187: return false;
	mov	dpl,#0x00
;	firmware.c:188: }
	ret
;------------------------------------------------------------
;Allocation info for local variables in function 'port_to_int8'
;------------------------------------------------------------
;port                      Allocated to registers r5 r6 r7 
;------------------------------------------------------------
;	firmware.c:190: int8_t port_to_int8(char *port) {
;	-----------------------------------------
;	 function port_to_int8
;	-----------------------------------------
_port_to_int8:
;	firmware.c:191: if (!is_port_allowed(port)) {
	mov	r5,dpl
	mov	r6,dph
	mov	r7,b
	push	ar7
	push	ar6
	push	ar5
	lcall	_is_port_allowed
	mov	a,dpl
	pop	ar5
	pop	ar6
	pop	ar7
	jnz	00102$
;	firmware.c:192: return -1;
	mov	dpl,#0xff
	ret
00102$:
;	firmware.c:195: return (int8_t)str_to_uint8(port);
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
;	firmware.c:196: }
	ljmp	_str_to_uint8
;------------------------------------------------------------
;Allocation info for local variables in function 'main'
;------------------------------------------------------------
;i                         Allocated to registers r6 r7 
;ch                        Allocated to registers r3 
;t                         Allocated with name '_main_t_131075_60'
;p                         Allocated to registers r3 r5 r6 
;write                     Allocated to registers r4 
;port                      Allocated to registers r7 
;req_len                   Allocated to registers r6 
;i                         Allocated to registers r5 
;ret                       Allocated to registers 
;ret                       Allocated to registers 
;i                         Allocated to registers r7 
;num                       Allocated with name '_main_num_327687_80'
;cmd                       Allocated with name '_main_cmd_65537_53'
;i2c_buf                   Allocated with name '_main_i2c_buf_65537_53'
;------------------------------------------------------------
;	firmware.c:200: int main(void) {
;	-----------------------------------------
;	 function main
;	-----------------------------------------
_main:
;	firmware.c:201: serial_print("Weather Station\n");
	mov	dptr,#___str_5
	mov	b,#0x80
	lcall	_serial_print
;	firmware.c:206: while (true) {
00135$:
;	firmware.c:207: serial_print("? ");
	mov	dptr,#___str_6
	mov	b,#0x80
	lcall	_serial_print
;	firmware.c:210: for (i = 0; i < CMD_BUF_SZ; i++) {
	mov	r6,#0x00
	mov	r7,#0x00
	mov	r4,#0x00
	mov	r5,#0x00
00137$:
;	firmware.c:211: char ch = serial_read_char();
	push	ar7
	push	ar6
	push	ar5
	push	ar4
	lcall	_serial_read_char
	mov	r3,dpl
	pop	ar4
	pop	ar5
	pop	ar6
	pop	ar7
;	firmware.c:212: if (ch == '\n') {
	cjne	r3,#0x0a,00102$
;	firmware.c:213: cmd[i] = '\0';
	mov	a,r6
	add	a,#_main_cmd_65537_53
	mov	dpl,a
	mov	a,r7
	addc	a,#(_main_cmd_65537_53 >> 8)
	mov	dph,a
	clr	a
	movx	@dptr,a
;	firmware.c:214: break;
	sjmp	00103$
00102$:
;	firmware.c:216: cmd[i] = ch;
	mov	a,r4
	add	a,#_main_cmd_65537_53
	mov	dpl,a
	mov	a,r5
	addc	a,#(_main_cmd_65537_53 >> 8)
	mov	dph,a
	mov	a,r3
	movx	@dptr,a
;	firmware.c:210: for (i = 0; i < CMD_BUF_SZ; i++) {
	inc	r4
	cjne	r4,#0x00,00246$
	inc	r5
00246$:
	mov	ar6,r4
	mov	ar7,r5
	clr	c
	mov	a,r4
	subb	a,#0x80
	mov	a,r5
	xrl	a,#0x80
	subb	a,#0x81
	jc	00137$
00103$:
;	firmware.c:219: if (i == CMD_BUF_SZ) {
	cjne	r6,#0x80,00105$
	cjne	r7,#0x01,00105$
;	firmware.c:220: serial_print("-err: command too long, rejected\n");
	mov	dptr,#___str_7
	mov	b,#0x80
	lcall	_serial_print
;	firmware.c:221: continue;
	sjmp	00135$
00105$:
;	firmware.c:225: tokenizer_init(&t, cmd);
	mov	_tokenizer_init_PARM_2,#_main_cmd_65537_53
	mov	(_tokenizer_init_PARM_2 + 1),#(_main_cmd_65537_53 >> 8)
	mov	(_tokenizer_init_PARM_2 + 2),#0x00
	mov	dptr,#_main_t_131075_60
	mov	b,#0x40
	lcall	_tokenizer_init
;	firmware.c:227: char *p = tokenizer_next(&t);
	mov	dptr,#_main_t_131075_60
	mov	b,#0x40
	lcall	_tokenizer_next
	mov	r5,dpl
	mov	r6,dph
	mov	r7,b
;	firmware.c:228: if (p == NULL) {
	mov	a,r5
	orl	a,r6
	jnz	00107$
;	firmware.c:229: serial_print("-err: command format incorrect\n");
	mov	dptr,#___str_8
	mov	b,#0x80
	lcall	_serial_print
;	firmware.c:230: continue;
	ljmp	00135$
00107$:
;	firmware.c:234: if (*p == 'r') {
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	lcall	__gptrget
	mov	r4,a
	cjne	r4,#0x72,00112$
;	firmware.c:235: write = false;
	mov	r4,#0x00
	sjmp	00113$
00112$:
;	firmware.c:236: } else if (*p == 'w') {
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	lcall	__gptrget
	mov	r5,a
	cjne	r5,#0x77,00109$
;	firmware.c:237: write = true;
	mov	r4,#0x01
	sjmp	00113$
00109$:
;	firmware.c:239: serial_print("-err: unknown command\n");
	mov	dptr,#___str_9
	mov	b,#0x80
	lcall	_serial_print
;	firmware.c:240: continue;
	ljmp	00135$
00113$:
;	firmware.c:243: p = tokenizer_next(&t);
	mov	dptr,#_main_t_131075_60
	mov	b,#0x40
	push	ar4
	lcall	_tokenizer_next
	mov	r5,dpl
	mov	r6,dph
	mov	r7,b
	pop	ar4
;	firmware.c:244: if (p == NULL) {
	mov	a,r5
	orl	a,r6
	jnz	00115$
;	firmware.c:245: serial_print("-err: command format incorrect\n");
	mov	dptr,#___str_8
	mov	b,#0x80
	lcall	_serial_print
;	firmware.c:246: continue;
	ljmp	00135$
00115$:
;	firmware.c:249: int8_t port = port_to_int8(p);
	mov	dpl,r5
	mov	dph,r6
	mov	b,r7
	push	ar4
	lcall	_port_to_int8
	mov	r7,dpl
	pop	ar4
;	firmware.c:250: if (port == -1) {
	cjne	r7,#0xff,00117$
;	firmware.c:251: serial_print("-err: port invalid or not allowed\n");
	mov	dptr,#___str_10
	mov	b,#0x80
	lcall	_serial_print
;	firmware.c:252: continue;
	ljmp	00135$
00117$:
;	firmware.c:255: p = tokenizer_next(&t);
	mov	dptr,#_main_t_131075_60
	mov	b,#0x40
	push	ar7
	push	ar4
	lcall	_tokenizer_next
	mov	r3,dpl
	mov	r5,dph
	mov	r6,b
	pop	ar4
	pop	ar7
;	firmware.c:256: if (p == NULL) {
	mov	a,r3
	orl	a,r5
	jnz	00119$
;	firmware.c:257: serial_print("-err: command format incorrect\n");
	mov	dptr,#___str_8
	mov	b,#0x80
	lcall	_serial_print
;	firmware.c:258: continue;
	ljmp	00135$
00119$:
;	firmware.c:261: uint8_t req_len = str_to_uint8(p);
	mov	dpl,r3
	mov	dph,r5
	mov	b,r6
	push	ar7
	push	ar4
	lcall	_str_to_uint8
	mov	r6,dpl
	pop	ar4
	pop	ar7
;	firmware.c:262: if (req_len == 0 || req_len > I2C_BUF_SZ) {
	mov	a,r6
	jz	00120$
	mov	a,r6
	add	a,#0xff - 0x80
	jnc	00121$
00120$:
;	firmware.c:263: serial_print("-err: I2C request length incorrect\n");
	mov	dptr,#___str_11
	mov	b,#0x80
	lcall	_serial_print
;	firmware.c:264: continue;
	ljmp	00135$
00121$:
;	firmware.c:267: if (write) {
	mov	a,r4
	jz	00132$
;	firmware.c:268: for (uint8_t i = 0; i < req_len; i++) {
	mov	r5,#0x00
00140$:
	clr	c
	mov	a,r5
	subb	a,r6
	jnc	00125$
;	firmware.c:269: p = tokenizer_next(&t);
	mov	dptr,#_main_t_131075_60
	mov	b,#0x40
	push	ar7
	push	ar6
	push	ar5
	lcall	_tokenizer_next
	mov	r2,dpl
	mov	r3,dph
	mov	r4,b
	pop	ar5
	pop	ar6
	pop	ar7
;	firmware.c:270: if (p == NULL) {
	mov	a,r2
	orl	a,r3
	jz	00125$
;	firmware.c:274: i2c_buf[i] = str_to_uint8(p);
	mov	a,r5
	add	a,#_main_i2c_buf_65537_53
	mov	r0,a
	clr	a
	addc	a,#(_main_i2c_buf_65537_53 >> 8)
	mov	r1,a
	mov	dpl,r2
	mov	dph,r3
	mov	b,r4
	push	ar7
	push	ar6
	push	ar5
	push	ar1
	push	ar0
	lcall	_str_to_uint8
	mov	r4,dpl
	pop	ar0
	pop	ar1
	pop	ar5
	pop	ar6
	pop	ar7
	mov	dpl,r0
	mov	dph,r1
	mov	a,r4
	movx	@dptr,a
;	firmware.c:268: for (uint8_t i = 0; i < req_len; i++) {
	inc	r5
	sjmp	00140$
00125$:
;	firmware.c:277: int8_t ret = i2c_write(port, req_len, i2c_buf);
	mov	_i2c_write_PARM_2,r6
	mov	_i2c_write_PARM_3,#_main_i2c_buf_65537_53
	mov	(_i2c_write_PARM_3 + 1),#(_main_i2c_buf_65537_53 >> 8)
	mov	dpl,r7
	lcall	_i2c_write
;	firmware.c:278: serial_print(i2c_status_to_error(ret));
	lcall	_i2c_status_to_error
	lcall	_serial_print
	ljmp	00135$
00132$:
;	firmware.c:280: int8_t ret = i2c_read(port, req_len, i2c_buf);
	mov	_i2c_read_PARM_3,#_main_i2c_buf_65537_53
	mov	(_i2c_read_PARM_3 + 1),#(_main_i2c_buf_65537_53 >> 8)
	mov	_i2c_read_PARM_2,r6
	mov	dpl,r7
	push	ar6
	lcall	_i2c_read
;	firmware.c:281: serial_print(i2c_status_to_error(ret));
	lcall	_i2c_status_to_error
	lcall	_serial_print
	pop	ar6
;	firmware.c:283: for (uint8_t i = 0; i < req_len; i++) {
	mov	r7,#0x00
00143$:
	clr	c
	mov	a,r7
	subb	a,r6
	jc	00264$
	ljmp	00130$
00264$:
;	firmware.c:285: uint8_to_str(num, i2c_buf[i]);
	mov	a,r7
	add	a,#_main_i2c_buf_65537_53
	mov	dpl,a
	clr	a
	addc	a,#(_main_i2c_buf_65537_53 >> 8)
	mov	dph,a
	movx	a,@dptr
	mov	_uint8_to_str_PARM_2,a
	mov	dptr,#_main_num_327687_80
	mov	b,#0x40
	push	ar7
	push	ar6
	lcall	_uint8_to_str
;	firmware.c:286: serial_print(num);
	mov	dptr,#_main_num_327687_80
	mov	b,#0x40
	lcall	_serial_print
	pop	ar6
	pop	ar7
;	firmware.c:288: if ((i + 1) % 16 == 0 && i +1 != req_len) {
	mov	ar4,r7
	mov	r5,#0x00
	mov	dpl,r4
	mov	dph,r5
	inc	dptr
	mov	__modsint_PARM_2,#0x10
;	1-genFromRTrack replaced	mov	(__modsint_PARM_2 + 1),#0x00
	mov	(__modsint_PARM_2 + 1),r5
	push	ar7
	push	ar6
	push	ar5
	push	ar4
	lcall	__modsint
	mov	a,dpl
	mov	b,dph
	pop	ar4
	pop	ar5
	pop	ar6
	pop	ar7
	orl	a,b
	jnz	00127$
	inc	r4
	cjne	r4,#0x00,00266$
	inc	r5
00266$:
	mov	ar2,r6
	mov	r3,#0x00
	mov	a,r4
	cjne	a,ar2,00267$
	mov	a,r5
	cjne	a,ar3,00267$
	sjmp	00127$
00267$:
;	firmware.c:289: serial_print("\n");
	mov	dptr,#___str_12
	mov	b,#0x80
	push	ar7
	push	ar6
	lcall	_serial_print
	pop	ar6
	pop	ar7
	sjmp	00144$
00127$:
;	firmware.c:291: serial_print(" ");
	mov	dptr,#___str_13
	mov	b,#0x80
	push	ar7
	push	ar6
	lcall	_serial_print
	pop	ar6
	pop	ar7
00144$:
;	firmware.c:283: for (uint8_t i = 0; i < req_len; i++) {
	inc	r7
	ljmp	00143$
00130$:
;	firmware.c:295: serial_print("\n-end\n");
	mov	dptr,#___str_14
	mov	b,#0x80
	lcall	_serial_print
;	firmware.c:300: }
	ljmp	00135$
	.area CSEG    (CODE)
	.area CONST   (CODE)
	.area CONST   (CODE)
___str_0:
	.ascii "i2c status: transaction completed / ready"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_1:
	.ascii "i2c status: busy"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_2:
	.ascii "i2c status: error - device not found"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_3:
	.ascii "i2c status: error - device misbehaved"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_4:
	.ascii "i2c status: unknown error"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_5:
	.ascii "Weather Station"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_6:
	.ascii "? "
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_7:
	.ascii "-err: command too long, rejected"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_8:
	.ascii "-err: command format incorrect"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_9:
	.ascii "-err: unknown command"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_10:
	.ascii "-err: port invalid or not allowed"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_11:
	.ascii "-err: I2C request length incorrect"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_12:
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_13:
	.ascii " "
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_14:
	.db 0x0a
	.ascii "-end"
	.db 0x0a
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_15:
	.ascii "101"
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_16:
	.ascii "108"
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_17:
	.ascii "110"
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_18:
	.ascii "111"
	.db 0x00
	.area CSEG    (CODE)
	.area CONST   (CODE)
___str_19:
	.ascii "119"
	.db 0x00
	.area CSEG    (CODE)
	.area XINIT   (CODE)
	.area CABS    (ABS,CODE)
