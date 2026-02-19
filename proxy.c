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
#include <parsec/parsec_mac.h>
#include <gssapi/gssapi.h>
#include "config.h"
#include "api.h"
#include "http.h"

#define BUF_SIZE 4096

pcfg cfg; //config.h


void token_validation(int fd);

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

void change_identity() {
	Labels mac_labels;
	if (get_labels(&mac_labels) != 0) error("Could not get mac label from freeipa");
	printf("min lvl - %hhd, max lvl - %hhd\n", mac_labels.min_lvl, mac_labels.max_lvl);
	
	struct _parsec_mac_t mac = {
		.cat = mac_labels.min_cat,
		.lev = mac_labels.min_lvl,
	};

	struct _parsec_mac_label_t mlabel = {
		.mac = mac,
		.type = 0,

	};


	pid_t pid = getpid();

	if (parsec_setmac(pid, &mac) != 0) error ("Could not set mac to child process, exiting...");
}


int main () {
	if (parse("./mrp.conf", &cfg) != 0) error("Could not load config, shutting down");

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
				 token_validation(client_sockfd);
				 change_identity();
				 handle_client(client_sockfd);
				 exit(0);
			default:
				 close(client_sockfd);
				 break;
		}
	}
}

void token_validation(int fd) {
	//send_response(fd);

	char token[8192];
	int res = http_read_header(fd, token);
	
	if (!res) {
		send_response(fd);
		res = http_read_header(fd, token);
	}	

	char raw_token[8192];
	int n = d_b64(token, raw_token);
	if (n <= 0) error ("b64 failed");

	gss_ctx_id_t context_hdl = GSS_C_NO_CONTEXT;
	struct gss_buffer_desc_struct input_token = {
		.length = n,
		.value = raw_token
	};
	gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
	OM_uint32 maj_stat, min_stat, ret_flags;
	gss_name_t client_name;

	maj_stat = gss_accept_sec_context(
			&min_stat, 
			&context_hdl, 
			GSS_C_NO_CREDENTIAL, 
			&input_token, 
			GSS_C_NO_CHANNEL_BINDINGS, 
			&client_name, 
			NULL, 
			&output_token, 
			&ret_flags, 
			NULL, 
			NULL
		);
	
	// somewhere here send 200 OK with encoded output token header, probably in a cycle

	//if (GSS_ERROR(maj_stat)) error("gssapi error");
	
	gss_buffer_desc name;

	maj_stat = gss_display_name(&min_stat, client_name, &name, NULL);
	if (maj_stat == GSS_S_COMPLETE) {
		printf("%s", (char*)name.value);
	}
	else error("gss auth not complete");
	gss_release_buffer(&min_stat, &name);
	gss_release_name(&min_stat, &client_name);
	gss_delete_sec_context(&min_stat, &context_hdl, GSS_C_NO_BUFFER);
}

