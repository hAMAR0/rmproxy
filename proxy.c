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


int token_validation(int fd);

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
				 int n = token_validation(client_sockfd);
				 if (n==0) {
					close(client_sockfd);
					exit(0);
				 }
				 change_identity();
				 handle_client(client_sockfd);
				 exit(0);
			default:
				 close(client_sockfd);
				 break;
		}
	}
}

int token_validation(int fd) {
	char req[65536];
	size_t req_len = 0;

	char b64_in[16384];
	char raw_in[16384];

	gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
	gss_name_t client_name = GSS_C_NO_NAME;
	OM_uint32 maj = 0, min = 0, ret_flags = 0;

	while (1) {
		if (!http_read_header(fd, req, sizeof(req), &req_len)) {
			break;
		}

		int tok_res = http_extract_negotiate_token(req, req_len, b64_in, sizeof(b64_in));
		if (tok_res == 0) {
			http_send_401(fd, NULL);
			continue;
		}
		if (tok_res < 0) {
			http_send_401(fd, NULL);
			break;
		}

		int in_len = d_b64(b64_in, raw_in, sizeof(raw_in));
		if (in_len <= 0) {
			http_send_401(fd, NULL);
			break;
		}

		gss_buffer_desc input_tok = { .length = (size_t)in_len, .value = raw_in };
		gss_buffer_desc output_tok = GSS_C_EMPTY_BUFFER;

		maj = gss_accept_sec_context(
			&min,
			&ctx,
			GSS_C_NO_CREDENTIAL,
			&input_tok,
			GSS_C_NO_CHANNEL_BINDINGS,
			&client_name,
			NULL,
			&output_tok,
			&ret_flags,
			NULL,
			NULL
		);
			
		if (GSS_ERROR(maj)) {
			http_send_401(fd, NULL);
			if (output_tok.length) gss_release_buffer(&min, &output_tok);
			break;
		}

		if (output_tok.length) {
			char b64_out[32768];
			int out_len = e_b64(output_tok.value, (int)output_tok.length, b64_out, sizeof(b64_out));
			gss_release_buffer(&min, &output_tok);

			if (out_len > 0) {
				if (maj & GSS_S_CONTINUE_NEEDED) {
					http_send_401(fd, b64_out);
					continue;
				}
			} else {
				http_send_401(fd, NULL);
				break;
			}
		}
		if (!GSS_ERROR(maj) && !(maj & GSS_S_CONTINUE_NEEDED)) {
			gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
			OM_uint32 mj2 = gss_display_name(&min, client_name, &name, NULL);
			if (mj2 != GSS_S_COMPLETE) {
				fprintf(stderr, "gss_display_name failed mj2=0x%08x min=0x%08x\n", mj2, min);
				break;
			}

			printf("user: %.*s\n", (int)name.length, (char*)name.value);

			gss_release_buffer(&min, &name);
			gss_release_name(&min, &client_name);
			gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
			return 1;
		}
	}

	if (client_name != GSS_C_NO_NAME) gss_release_name(&min, &client_name);
	if (ctx != GSS_C_NO_CONTEXT) gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
	return 0;
}
