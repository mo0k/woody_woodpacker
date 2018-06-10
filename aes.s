section .data
	Key_Tmp db 16
	Key_Schedule db 16*10
	Key_Schedule_Decrypt db 16*10

section .text
	global _expand_key128
	global _encrypt_128
	global _decrypt_128

_expand_key128: ;void expand_key128(uint8_t *key);

		;movdqu Key_Tmp, [rel rdi] 			;save key
		;movdqu xmm1, [rel Key_Tmp]		;place key dans xmm1
		;movdqu xmm1, [rel rdi]		;place key dans xmm1
	lea rdi, [rel Key_Schedule] 			;place tab_key dans rdi
		;movdqu xmm1, [rel rsi]
	movdqu [rel rdi], xmm1 			
	add rdi, 0x10
	aeskeygenassist xmm2, xmm1, 0x1
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x2
	call key_expansion_128 
	aeskeygenassist xmm2, xmm1, 0x4 
	call key_expansion_128 
	aeskeygenassist xmm2, xmm1, 0x8 
	call key_expansion_128 
	aeskeygenassist xmm2, xmm1, 0x10 
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x20 
	call key_expansion_128 
	aeskeygenassist xmm2, xmm1, 0x40
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x80 
	call key_expansion_128 
	aeskeygenassist xmm2, xmm1, 0x1b 
	call key_expansion_128 
	aeskeygenassist xmm2, xmm1, 0x36
	call key_expansion_128
	ret

key_expansion_128:
	pshufd xmm2, xmm2, 0xff
	vpslldq xmm3, xmm1, 0x4
	pxor xmm1, xmm3
	vpslldq xmm3, xmm1, 0x4
	pxor xmm1, xmm3
	vpslldq xmm3, xmm1, 0x4
	pxor xmm1, xmm3
	pxor xmm1, xmm2
	movdqu [rel rdi], xmm1
	add rdi, 0x10
	ret

_set_keys:
	movdqu xmm0, [rel rdi]
	movdqu xmm1, [rel rdi + 0x10]
	movdqu xmm2, [rel rdi + 0x20]
	movdqu xmm3, [rel rdi + 0x30]
	movdqu xmm4, [rel rdi + 0x40]
	movdqu xmm5, [rel rdi + 0x50]
	movdqu xmm6, [rel rdi + 0x60]
	movdqu xmm7, [rel rdi + 0x70]
	movdqu xmm8, [rel rdi + 0x80]
	movdqu xmm9, [rel rdi + 0x90]
	movdqu xmm10, [rel rdi + 0xa0]
	ret

_encrypt_128: ;void encrypt_128(void *block, uint8_t *ctx_key)

	xchg rsi, rdi
	;comparer le contenu de rdi (ct_key) et Key_Tmp
	;je apres _expand_key128
	call _expand_key128
	call _set_keys
	movdqu xmm15, [rel rsi]
	pxor xmm15, xmm0
	aesenc xmm15, xmm1
	aesenc xmm15, xmm2
	aesenc xmm15, xmm3
	aesenc xmm15, xmm4
	aesenc xmm15, xmm5
	aesenc xmm15, xmm6
	aesenc xmm15, xmm7
	aesenc xmm15, xmm8
	aesenc xmm15, xmm9
	aesenclast xmm15, xmm10
	movdqu [rel rsi], xmm15
	ret

_decrypt_128: ; void decrypt_128(void *block, uint8_t *ctx);
	
	xchg rsi, rdi
	;comparer le contenu de rdi (ct_key) et Key_Tmp
	;je apres _expand_key128
	call _expand_key128
	;call key_decrypt_expansion_128
	call _set_keys
	movdqu xmm15, [rel rsi]
	pxor xmm15, xmm10
	aesimc xmm9, xmm9
	aesdec xmm15, xmm9
	aesimc xmm8, xmm8
	aesdec xmm15, xmm8
	aesimc xmm7, xmm7
	aesdec xmm15, xmm7
	aesimc xmm6, xmm6
	aesdec xmm15, xmm6
	aesimc xmm5, xmm5
	aesdec xmm15, xmm5
	aesimc xmm4, xmm4
	aesdec xmm15, xmm4
	aesimc xmm3, xmm3
	aesdec xmm15, xmm3
	aesimc xmm2, xmm2
	aesdec xmm15, xmm2
	aesimc xmm1, xmm1
	aesdec xmm15, xmm1
	aesdeclast xmm15, xmm0
	movdqu [rel rsi], xmm15
	ret

