section .data
	Key_Schedule db 16*10
	Key_Schedule_Decrypt db 16*10

section .text
	global _expand_key128
	global _ft_encrypt
	global _ft_decrypt


;##############################################################################
;############################### EXPAND KEY ###################################
_expand_key:
	aeskeygenassist xmm2, xmm1, 0x0
	call key_expansion_128
	dec rcx
	CMP rcx, 0x0
	ja _expand_key
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
;############################### FT_ENCRYPT ###################################

_ft_encrypt: ; ###### void ft_encrypt(void *src, void *key) ######
	XCHG rsi, rdi
	movdqu xmm1, [rdi]
	lea rdi, [rel Key_Schedule]
	movdqu [rdi], xmm1
	add rdi, 0x10
	mov rcx, 0x10
	call _expand_key
	call _set_xmm
	movdqu xmm15, [rsi]
	pxor xmm15, 	  xmm0
	aesenc xmm15,     xmm1
	aesenc xmm15,     xmm2
	aesenc xmm15,     xmm3
	aesenc xmm15,     xmm4
	aesenc xmm15,     xmm5
	aesenc xmm15,     xmm6
	aesenc xmm15,     xmm7
	aesenc xmm15,     xmm8
	aesenc xmm15,     xmm9
	aesenclast xmm15, xmm10
	movdqu [rsi], xmm15
	ret

_set_xmm:
	lea rdi, [rel Key_Schedule]
	movdqu xmm0, [rdi]
	movdqu xmm1, [rdi+0x10]
	movdqu xmm2, [rdi+0x20]
	movdqu xmm3, [rdi+0x30]
	movdqu xmm4, [rdi+0x40]
	movdqu xmm5, [rdi+0x50]
	movdqu xmm6, [rdi+0x60]
	movdqu xmm7, [rdi+0x70]
	movdqu xmm8, [rdi+0x80]
	movdqu xmm9, [rdi+0x90]
	movdqu xmm10, [rdi+0xa0]
	ret

;##############################################################################
;############################### FT_DECRYPT ###################################

_ft_decrypt: ; void ft_decrypt(void *src, uint8_t *ctx);
	XCHG rsi, rdi
	movdqu xmm1, [rdi]
	lea rdi, [rel Key_Schedule]
	movdqu [rdi], xmm1
	add rdi, 0x10
	mov rcx, 10
	call _expand_key
	call _set_xmm
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
	movdqu [rsi], xmm15
	ret
_k:
	toto dq _k - _ft_decrypt
