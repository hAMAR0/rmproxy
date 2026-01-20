#include <stdlib.h>
#include <sys/poll.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <poll.h>
#include "config.h"
#include "api.h"

#define BUF_SIZE 4096

pcfg cfg; //config.h

void error(const char *msg) {
	perror(msg);
	exit(1);
}

void bridge(int client_fd, int stream_fd){
	struct pollfd fds[2];

	// client pollfd
	fds[0].fd = client_fd;
	fds[0].events = POLLIN;

	// server pollfd
	fds[1].fd = stream_fd;
	fds[1].events = POLLIN;

	char buffer[BUF_SIZE];

	while(1){
		int r = poll(fds, 2, -1);
		if (r<0) {
			perror("polling error");
			break;
		}

		// client -> stream
		if (fds[0].revents & POLLIN) {
			int n = read(client_fd, buffer, BUF_SIZE);
			if (n<=0) break;
			write(stream_fd, buffer, n);
		}

		// stream -> client
		if (fds[1].revents &POLLIN) {
			int n = read(stream_fd, buffer, BUF_SIZE);
			if (n<=0) break;
			write(client_fd, buffer, n);
		}
	}
	close(client_fd);
	close(stream_fd);
}

void handle_client(int client_fd) {
	int stream_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (stream_fd < 0) error("Error opening stream socket");

	struct sockaddr_in target_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(cfg.t_port)
	};
	if (inet_pton(AF_INET, cfg.t_addr, &target_addr.sin_addr) <= 0) error ("invalid stream address");

	if (connect(stream_fd, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
		perror("Connection to backend failed");
		close(client_fd);
		close(stream_fd);
		return;
	}
	bridge(client_fd, stream_fd);
}

void handle_sigchld(int s) {
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

int main () {
	if (parse("./mrp.conf", &cfg) != 0) error("Could not load config, shutting down");

	// solely for testing, will remove later
	Labels mac_labels;
	if (get_labels(&mac_labels) != 0) error("Could not get mac label from freeipa");
	printf("min lvl - %hhd, max lvl - %hhd", mac_labels.min_lvl, mac_labels.max_lvl);

	// killing every child when they exit via sigaction
	struct sigaction sa = {
		.sa_handler = handle_sigchld,
		.sa_flags = SA_RESTART
	};
	sigaction(SIGCHLD, &sa, NULL);

	// sockets
	int server_sockfd, client_sockfd;

	server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_sockfd < 0) error ("Error opening listening socket");

	int opt = 1;
	setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in server_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_ANY,
		.sin_port = htons(cfg.port)
	};

	if (bind(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) error("Could not bind socket");

	listen(server_sockfd, 128);
	printf("Listening on port %d\n", cfg.port);

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
				 handle_client(client_sockfd);
				 exit(0);
			default:
				 close(client_sockfd);
				 break;
		}
	}
}

