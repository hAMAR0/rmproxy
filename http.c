#include <stdio.h>
#include <string.h>
#include <unistd.h>

int find_header_end(char *buf, int n) {
	for (int i = 3; i < n; i++) {
		if (buf[i-3] == '\r' && buf[i-2] == '\n' && buf[i-1] == '\r' && buf[i] == '\n') {
			return i+1;
		}
	}
	return -1;
}


int http_read_header(int fd) {
	char buf[8192];
	// one read() might not get all headers, might as well dynamically allocate memory for buffer
	int n = read(fd, buf, sizeof(buf));
	int end = find_header_end(buf, sizeof(buf));
	//parse here
}

