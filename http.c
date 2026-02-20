#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "http.h"


int get_token(char* buf, char* ktoken);

int http_read_header(int fd, char* buf, size_t buf_size, size_t* output_len) {
	if (!buf) return 0;
	*output_len = 0;

	while (*output_len + 1 < buf_size) {
		ssize_t n = read(fd, buf + *output_len, buf_size - 1 - *output_len);
		if (n <= 0) return 0;
		*output_len += n;
		buf[*output_len] = '\0';
		if (strstr(buf, "\r\n\r\n") != NULL) return 1;

	}

	return 0;
}

int http_send_401(int fd, const char* b64tok) {
	char response[16384];
	int n;

	if (b64tok && b64tok[0] != '\0') {
		n = snprintf(
			response, sizeof(response),
			"HTTP/1.1 401 Unauthorized\r\n"
			"WWW-Authenticate: Negotiate %s\r\n"
			"Content-Length: 0\r\n"
			"Connection: keep-alive\r\n\r\n",
			b64tok
		);
	}
	else {
		n = snprintf(
			response, sizeof(response),
			"HTTP/1.1 401 Unauthorized\r\n"
			"WWW-Authenticate: Negotiate\r\n"
			"Content-Length: 0\r\n"
			"Connection: keep-alive\r\n\r\n"
		);
	}

	if (n <= 0) return 0;

	write(fd,response, n);

	return 1;
}

int http_extract_negotiate_token(const char* headers, size_t headers_len, char* out_tok, size_t out_tok_sz) {
	if (!headers || !out_tok || out_tok_sz == 0) return -1;
	out_tok[0] = '\0';

	const char* p = strstr(headers, "\r\nAuthorization:");
	if (!p) {
		if (strncasecmp(headers, "Authorization:", 14) != 0) return 0;
		p = headers;
	} else {
		p += 2;
	}

	const char* line_end = strstr(p, "\r\n");
	if (!line_end) return -1;

	const char* scheme = strstr(p, "Authorization: Negotiate ");
	if (!scheme) return 0;

	const char* tok_start = scheme + strlen("Authorization: Negotiate ");
	while (tok_start < line_end && (*tok_start == ' ' || *tok_start == '\t')) tok_start++;
	if (tok_start >= line_end) return -1;

	size_t tok_len = (size_t)(line_end - tok_start);
	if (tok_len + 1 > out_tok_sz) return -1;

	memcpy(out_tok, tok_start, tok_len);
	out_tok[tok_len] = '\0';
	return 1;
}

int d_b64(const char* input, char* out, size_t out_sz) {
	if (!input || !out || out_sz == 0) return 0;
	int in_len = (int)strlen(input);

	BIO* bio_mem = BIO_new_mem_buf((void*)input, in_len);
	BIO* bio_b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
	bio_b64 = BIO_push(bio_b64, bio_mem);

	int d_len = BIO_read(bio_b64, (void*)out, (int)out_sz);
	BIO_free_all(bio_b64);

	if (d_len <= 0) return 0;
	return d_len;
}

int e_b64(const void* input, int input_len, char* out, size_t out_sz) {
	if (!input || input_len <= 0 || !out || out_sz == 0) return 0;

	BIO* bio_mem = BIO_new(BIO_s_mem());
	BIO* bio_b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
	bio_b64 = BIO_push(bio_b64, bio_mem);

	if (BIO_write(bio_b64, input, input_len) <= 0) {
		BIO_free_all(bio_b64);
		return 0;
	}
	(void)BIO_flush(bio_b64);

	BUF_MEM* bptr = NULL;
	BIO_get_mem_ptr(bio_mem, &bptr);
	if (!bptr || !bptr->data || bptr->length + 1 > out_sz) {
		BIO_free_all(bio_b64);
		return 0;
	}

	memcpy(out, bptr->data, bptr->length);
	out[bptr->length] = '\0';

	int out_len = (int)bptr->length;
	BIO_free_all(bio_b64);
	return out_len;
}
