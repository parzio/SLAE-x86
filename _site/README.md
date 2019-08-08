# x86 Assembly Language and Shellcoding on Linux

I recently registered to the SLAE course for improving my skills with regards to Assembly language and Shellcoding.
Once completed the course, which I found very instructive and curated, I decided to go for the related certification.

Hereafter the assignments to be completed and to be published online to successfully earning the certification.

## Assignment 1

* Create a Shell_Bind_TCP shellcode
  * Binds to a port
  * Execs shell on incoming connections
* Port number should be easily configurable

[Execution](00_bindshell/README.md)

## Assignment 2

* Create a Shell_Reverse_TCP shellcode
  * Reverse connects to a configured IP and Port
  * Execs shell on successful connection
* IP and Port should be easily configurable

[Execution](01_revshell/README.md)

## Assignment 3

* Study about Egg Hunters shellcode
* Create a working demo of the Egghunter
* Should be configurable for different payloads

[Execution](02_egghunter/README.md)

## Assignment 4

* Create a custom encoding scheme like the "Insertion Encoder" we showed you
* PoC with using the execve-stack as the shellcode to encode with your schema and execute

[Execution](03_encoder/README.md)

## Assignment 5

* Take up at least 3 shellcode samples created using the Msfpayload for linux/x86
* Use GDB/Disasm/Libemu to dissect the functionality of the shellcode
* Present your analysis

[Execution](04_payloads_analysis/README.md)

## Assignment 6

* Take up 3 shellcodes from Shell-Storm and create a polymorphic version of them to beat pattern matching
* The polymorphic version cannot be larger 150% of the existing shellcode
* Bonus point for making it shorter in length than original

[Execution](05_polymorphic_shellcode/README.md)

## Assignment 7

* Create a custom crypter like the one shown in the "crypters" video
* Free to use any encryption schema 
* Can use any programming language

[Execution](06_crypter/README.md)

<br/>

Well, this concludes the list of assignments completed for concluding the SLAE x86 course! Very nice journey, I learned a ton! Thank you Vivek Ramachandran!

<br/>

*************************

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.

<http://securitytube-training.com/online-courses/securit-tube-linux-assembly-expert>

Student-ID: PA-8733
