#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "http.h"

int get_token(char* buf, char* ktoken);

int http_read_header(int fd, char* dest_token) {
	char buf[8192];
	int n = read(fd, buf, sizeof(buf));

	char token[4096];
	if (get_token(buf, dest_token) != 0) {
		printf("%s", "Could not get token");
	}
	return 0;
}

int send_response(int fd) {
	char response[] = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
	int n = write(fd, response, sizeof(response));
	return 0;
}

int get_token(char* buf, char* ktoken) {
	char* line_end = strstr(buf, "\r\n");
	char line[128];
	int len = line_end - buf;
	strncpy(line, buf, len);

	char method[16], route[16], protocol[16];

	line[len] = '\0';
	sscanf(line, "%s %s %s", method, route, protocol);
	printf("%s\n%s\n%s\n", method, route, protocol);


	char token[4096];
	char *auth = strstr(buf, "Authorization: Negotiate ");
	auth+=25;
	line_end = strstr(auth, "\r\n");
	len = line_end - auth;
	strncpy(token, auth, len);
	token[len] = '\0';
	ktoken = token;
	return 0;
}
