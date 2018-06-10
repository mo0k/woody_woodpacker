section .data
	Key_Schedule db 16*10
	Key_Schedule_Decrypt db 16*10

section .text
	global _expand_key128
	global _encrypt_128
	global _decrypt_128


;##############################################################################
;############################### EXPAND KEY ###################################
_expand_key128:
	aeskeygenassist xmm2, xmm1, 0x0
	call key_expansion_128
	dec rcx
	CMP rcx, 0x0
	ja _expand_key128
	ret

key_expansion_128:
	pshufd xmm2, xmm2, 0xFF
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
;##############################################################################
;##############################################################################

_encrypt_128: ; ###### void encrypt_128(void *data, uint8_t *ctx_key) ######
	XCHG rsi, rdi
	lea rdi, [rel Key_Schedule]
	movdqu [rel rdi], xmm1
	add rdi, 0x10
	mov rcx, 10				;;;;;; ###### Compteur boucle [EXPAND KEY ] #######
	call _expand_key128
	movdqu xmm15, [rel rsi]
	pxor xmm15, [rdi]
	aesenc xmm15, [rdi+0x10]
	aesenc xmm15, [rdi+0x20]
	aesenc xmm15, [rdi+0x30]
	aesenc xmm15, [rdi+0x40]
	aesenc xmm15, [rdi+0x50]
	aesenc xmm15, [rdi+0x60]
	aesenc xmm15, [rdi+0x70]
	aesenc xmm15, [rdi+0x80]
	aesenc xmm15, [rdi+0x90]
	aesenclast xmm15, [rdi+0xa0]
	movdqu [rel rsi], xmm15
	ret

_decrypt_128: ; void decrypt_128(void *block, uint8_t *ctx);
	XCHG rsi, rdi
	lea rdi, [rel Key_Schedule]
	movdqu [rel rdi], xmm1
	add rdi, 0x10
	mov rcx, 10
	call _expand_key128
	movdqu xmm15, [rel rsi]
	pxor xmm15, [rdi+0xa0]
	aesimc xmm9, [rdi+0x90]
	aesdec xmm15, xmm9
	aesimc xmm8, [rdi+0x80]
	aesdec xmm15, xmm8
	aesimc xmm7, [rdi+0x70]
	aesdec xmm15, xmm7
	aesimc xmm6, [rdi+0x60]
	aesdec xmm15, xmm6
	aesimc xmm5, [rdi+0x50]
	aesdec xmm15, xmm5
	aesimc xmm4, [rdi+0x40]
	aesdec xmm15, xmm4
	aesimc xmm3, [rdi+0x30]
	aesdec xmm15, xmm3
	aesimc xmm2, [rdi+0x20]
	aesdec xmm15, xmm2
	aesimc xmm1, [rdi+0x10]
	aesdec xmm15, xmm1
	aesdeclast xmm15, [rdi]
	movdqu [rel rsi], xmm15
	ret

