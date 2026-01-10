#include <bits/sockaddr.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>

#define LISTEN_PORT 8000
#define BUF_SIZE 4096

void error(const char *msg) {
	perror(msg);
	exit(1);
}

void handle_sigchld(int s) {
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

int main () {
	// killing every children when they exit via sigaction
	struct sigaction sa = {
		.sa_handler = handle_sigchld,
		.sa_flags = SA_RESTART
	};
	sigaction(SIGCHLD, &sa, NULL);

	// sockets
	int server_sockfd, client_sockfd;
	char buffer[BUF_SIZE];

	server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_sockfd < 0) error ("Error opening listening socket");

	int opt = 1;
	setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in server_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_ANY,
		.sin_port = htons(LISTEN_PORT)
	};

	if (bind(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) error("Could not bind socket");

	listen(server_sockfd, 128);
	printf("Listening on port %d\n", LISTEN_PORT);

	// main loop
	struct sockaddr_in client_addr;
	while (1) {
		socklen_t client_len = sizeof(client_addr);
		client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_addr, &client_len);
		if (client_sockfd < 0){ 
			perror("Could not accept connection");
			continue;
		}
		
		switch(fork()) {
			case -1: 
			close(client_sockfd);
				break;
			case 0:
				 close(server_sockfd);
				 //handle_client();
				 exit(0);
			default:
				 close(client_sockfd);
				 break;
		}
	}
}

