#include <stdlib.h>
#include <string.h>
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
#include <parsec/mac.h>

#include <gssapi/gssapi.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "config.h"
#include "sssd.h"
#include "http.h"

#define BUF_SIZE 4096

static char prefetch_req[65536];
static size_t prefetch_len = 0;

pcfg cfg; //config.h
void error(const char *msg) {
	perror(msg);
	exit(1);
}

int token_validation(SSL *ssl, char* out_name, char* fqdn) {
	char req[65536];
	size_t req_len = 0;
	char host[512];

	char b64_in[16384];
	char raw_in[16384];

	gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
	gss_name_t client_name = GSS_C_NO_NAME;
	OM_uint32 maj = 0, min = 0, ret_flags = 0;

	while (1) {
		if (!http_read_header(ssl, req, sizeof(req), &req_len)) {
			break;
		}
		
		if (http_get_host(req, host, sizeof(host))) {
			strcpy(fqdn, host);
		}


		int tok_res = http_extract_negotiate_token(req, req_len, b64_in, sizeof(b64_in));
		if (tok_res == 0) {
			http_send_401(ssl, NULL);
			continue;
		}
		if (tok_res < 0) {
			http_send_401(ssl, NULL);
			break;
		}

		int in_len = d_b64(b64_in, raw_in, sizeof(raw_in));
		if (in_len <= 0) {
			http_send_401(ssl, NULL);
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
			http_send_401(ssl, NULL);
			if (output_tok.length) gss_release_buffer(&min, &output_tok);
			break;
		}

		if (output_tok.length) {
			char b64_out[32768];
			int out_len = e_b64(output_tok.value, (int)output_tok.length, b64_out, sizeof(b64_out));
			gss_release_buffer(&min, &output_tok);

			if (out_len > 0) {
				if (maj & GSS_S_CONTINUE_NEEDED) {
					http_send_401(ssl, b64_out);
					continue;
				}
			} else {
				http_send_401(ssl, NULL);
				break;
			}
		}
		if (!GSS_ERROR(maj) && !(maj & GSS_S_CONTINUE_NEEDED)) {
			gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
			OM_uint32 mj2 = gss_display_name(&min, client_name, &name, NULL);
			if (mj2 != GSS_S_COMPLETE) {
				break;
			}

			strcpy(out_name, (char*)name.value);
			out_name[(int)name.length] = '\0';

			if (req_len > sizeof(prefetch_req)) req_len = sizeof(prefetch_req);
			memcpy(prefetch_req, req, req_len);
			prefetch_len = req_len;

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

void bridge(SSL *ssl, int stream_fd) {
	int client_fd = SSL_get_fd(ssl);
	struct pollfd fds[2];

	// client pollfd
	fds[0].fd = client_fd;
	fds[0].events = POLLIN;

	// server pollfd
	fds[1].fd = stream_fd;
	fds[1].events = POLLIN;

	char buffer[BUF_SIZE];

	while(1){
		int r;
		if (SSL_pending(ssl) > 0) {
			r = 1;
			fds[0].revents = POLLIN;
			fds[1].revents = 0;
		}
		else {
			r = poll(fds, 2, -1);
		}
	
		if (r<0) {
			perror("polling error");
			break;
		}
		// client -> stream
		if (fds[0].revents & POLLIN || SSL_pending(ssl) > 0) {
			int n = SSL_read(ssl, buffer, BUF_SIZE);
			if (n<=0) break;
			write(stream_fd, buffer, n);
		}

		// stream -> client
		if (fds[1].revents &POLLIN) {
			int n = read(stream_fd, buffer, BUF_SIZE);
			if (n<=0) break;
			SSL_write(ssl, buffer, n);
		}
	}
	close(stream_fd);
}

void handle_client(SSL *ssl, const char* prefetch, size_t prefetch_size) {
	int stream_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (stream_fd < 0) error("Error opening stream socket");

	struct sockaddr_in target_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(cfg.t_port)
	};
	if (inet_pton(AF_INET, cfg.t_addr, &target_addr.sin_addr) <= 0) error ("invalid stream address");

	if (connect(stream_fd, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
		perror("Connection to backend failed");
		close(stream_fd);
		return;
	}

	if (prefetch) {
		ssize_t n = write(stream_fd, prefetch, prefetch_size);
		if (n < 0) {
			perror("error writing prefetch");
			close(stream_fd);
			return;
		}
	}
	bridge(ssl, stream_fd);
}

void handle_sigchld(int s) {
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

int get_mac_part(char* input, char* min, char* max) {
	char* col1 = strchr(input, ':');
	char* col2 = strchr(col1+1, ':');
	if (col2) {
		int len1 = col2 - input;
		strncpy(min, input, len1);
		min[len1] = '\0';
		strcpy(max, col2+1);
		return 1;
	}
	return 0;
}

void change_identity(char* uname, char* fqdn, SSL *ssl, char* clienthost) {
	char* mac_str_user = get_sssd_attr(uname, "x-ald-user-mac");
	char mac_str_host[32];

	char host_srv_fqdn[256] = {0};
	strcpy(host_srv_fqdn, cfg.dc_url);
	ldap_get_host_mac(host_srv_fqdn, mac_str_host);

	char mac_str_userhost[32];
	ldap_get_host_mac(clienthost, mac_str_userhost);

	//TODO: ldap_get_host_mac() is much slower than getting values from sssd cache, USE JWT;

	char mac_str_user_min[16], mac_str_user_max[16], mac_str_host_min[16], mac_str_host_max[16], mac_str_userhost_min[16], mac_str_userhost_max[16];
	
	if (get_mac_part(mac_str_user, mac_str_user_min, mac_str_user_max) == 0 || get_mac_part(mac_str_host, mac_str_host_min, mac_str_host_max) == 0 || get_mac_part(mac_str_userhost, mac_str_userhost_min, mac_str_userhost_max) == 0) {
		error("Could not parse minmax mac");
	}
	printf("user %s\nhost %s\nuserhost %s\n", mac_str_user, mac_str_host, mac_str_userhost);

	mac_t userhost_mac = mac_init(MAC_TYPE_SUBJECT); // user machine fqdn
	mac_t user_mac = mac_init(MAC_TYPE_SUBJECT); // user
	mac_t host_mac = mac_init(MAC_TYPE_SUBJECT); // requested destination fqdn
	
	if (mac_from_text(user_mac, mac_str_user_min) < 0 || mac_from_text(host_mac, mac_str_host_min) < 0 || mac_from_text(userhost_mac, mac_str_userhost_min)) error ("Could not set user mac");

	if(mac_cmp(user_mac, userhost_mac) != 0) {
		printf("User tried accessing website with MAC level stronger/lower than the logged in machine\n");
		return;
	}

	pid_t pid = getpid();
	switch(mac_cmp(user_mac, host_mac)){
		case -2:
			mac_free(user_mac);
			mac_free(host_mac);
			error("mac labels are not comparable");
			break;
		case -1:
			mac_free(user_mac);
			mac_free(host_mac);
			printf("user mac < host mac\n");
			break;
		case 0:
			printf("user mac = host mac\n");
			if (mac_set_pid(pid, user_mac) != 0) {
				error ("Could not set mac to child process");
			}
			handle_client(ssl, prefetch_req, prefetch_len);
			mac_free(user_mac);
			mac_free(host_mac);

			break;
		case 1:
			printf("user mac > host mac\n");
			handle_client(ssl, prefetch_req, prefetch_len);
			mac_free(user_mac);
			mac_free(host_mac);
			break;
		default:
			mac_free(user_mac);
			mac_free(host_mac);
			printf("some other error");
			break;
	}
}


int main () {
	// init ssl
	SSL_CTX *ctx;
	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL) {
		error("Failed to create server ssl_ctx");
	}
	if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
		SSL_CTX_free(ctx);
		error("Failed to set minimum TLS protocol version");
	}

	uint32_t opts = 0;
	opts = SSL_OP_IGNORE_UNEXPECTED_EOF;
	opts |= SSL_OP_NO_RENEGOTIATION;
	opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;
	SSL_CTX_set_options(ctx, opts);

	//TODO: move cert path to cfg
	if (SSL_CTX_use_certificate_file(ctx, "./cert/cert.pem", SSL_FILETYPE_PEM) < 1 || SSL_CTX_use_PrivateKey_file(ctx, "./cert/key.pem", SSL_FILETYPE_PEM) < 1) {
		SSL_CTX_free(ctx);
		error("Failed to load certificates");
	}


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
		
		char clienthost[1024];
		
		switch(fork()) {
			case -1:
			close(client_sockfd);
				break;
			case 0:
				close(server_sockfd);
				
				if (getnameinfo((struct sockaddr *)&client_addr, sizeof(client_addr), clienthost, sizeof(clienthost), NULL, 0, 0) != 0) {
					error("Could not get user fqdn");
				}
				printf("FQDN of the user machine: %s\n", clienthost);

				SSL *ssl = SSL_new(ctx);
				SSL_set_fd(ssl, client_sockfd);
				if (SSL_accept(ssl) <= 0) {
					ERR_print_errors_fp(stderr);
					SSL_shutdown(ssl);
					SSL_free(ssl);
					close(client_sockfd);
					exit(1);
				}
				

				char uname[512];
				char fqdn[512];
				token_validation(ssl, uname, fqdn);
				change_identity(uname, fqdn, ssl, clienthost);
				exit(0);
			default:
				close(client_sockfd);
				break;
		}
	}
}
