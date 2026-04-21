#define _GNU_SOURCE
#include <openssl/crypto.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include "http.h"

int get_token(char* buf, char* ktoken);

int http_read_header(SSL *ssl, char* buf, size_t buf_size, size_t* output_len) {
	if (!buf) return 0;
	*output_len = 0;

	while (*output_len + 1 < buf_size) {
		int n = SSL_read(ssl, buf + *output_len, buf_size - 1 - *output_len);
		if (n <= 0) return 0;
		*output_len += n;
		buf[*output_len] = '\0';
		if (strstr(buf, "\r\n\r\n") != NULL) return 1;

	}

	return 0;
}

int http_send_401(SSL *ssl, const char* b64tok) {
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

	if (SSL_write(ssl, response, n) <= 0) return 0;

	return 1;
}
int http_get_host(const char *headers, char *out, size_t max_len) {
    const char *p = strcasestr(headers, "Host:");
    if (!p) return 0;
    p += 5; 
    while (*p == ' ' || *p == '\t') p++;

    size_t i = 0;
    while (p[i] != '\r' && p[i] != '\n' && p[i] != ':' && p[i] != '\0') {
        if (i < max_len - 1) {
            out[i] = p[i];
            i++;
        } else {
            break;
        }
    }
    out[i] = '\0';
    return (i > 0);
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


#define JWT_SECRET "rmproxysecret"

int create_signature(char* data, char* out_b64, size_t out_sz) {
	unsigned char hash[32];
	unsigned int len;

	HMAC(EVP_sha256(), JWT_SECRET, strlen(JWT_SECRET), (unsigned char*)data, strlen(data), hash, &len);

	return e_b64(hash, len, out_b64, out_sz);
}

void wrapper(char* b64_data, int b64_sz) {
	for (int i = 0; i < b64_sz; i++) {
		switch (b64_data[i]) {
			case '+':
				b64_data[i] = '-';
				break;
			case '/':
				b64_data[i] = '_';
				break;
			case '=':
				b64_data[i] = '\0';
				break;
			default:
			break;
		}
	}
}

void unwrapper(char* b64_data, int b64_sz, char* out_b, int out_s) {
	if (out_s < b64_sz + 4) return;

	for (int i = 0; i < b64_sz; i++) {
		switch (b64_data[i]) {
			case '-':
				out_b[i] = '+';
				break;
			case '_':
				out_b[i] = '/';
				break;
			default:
				out_b[i] = b64_data[i];
				break;
		}
	}

	int pad = 4 - (b64_sz % 4);
	if (pad == 4) pad = 0;
	for (int i = 0; i < pad; i++) {
		out_b[b64_sz+i] = '=';
	}
	out_b[b64_sz + pad] = '\0';
}

int create_jwt(char* payload, char* jwt) {
	char b64_data[256];
	int b64_sz = sizeof(b64_data);
	
	char output[512];

	char* header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; //default jwt header hardcoded

	int nn = e_b64(payload, strlen(payload), b64_data, b64_sz);
	wrapper(b64_data, nn);
	
	snprintf(output, sizeof(output), "%s.%s", header, b64_data);
	
	char b64d[256];
	int b64s = sizeof(b64d);
	int n = create_signature(output, b64d, b64s);
	wrapper(b64d, n);
	
	char out[512];
	snprintf(out, sizeof(out), "%s.%s", output, b64d);
	snprintf(jwt, sizeof(out), "%s", out);

	return 1;
}

int check_jwt(char* jwt) {
	char header[128], payload[256], signature[256];
	sscanf(jwt, "%127[^.].%127[^.].%127[^.]", header, payload, signature);

	char outp[256], outpd[256];
	snprintf(outp, sizeof(outp), "%s.%s", header, payload);
	int sig_n = create_signature(outp, outpd, sizeof(outpd));
	wrapper(outpd, sig_n);

	return CRYPTO_memcmp(outpd, signature, strlen(signature)) == 0;
}

int http_extract_jwt_cookie(const char* headers, char* out, size_t out_sz) {
	const char* p = strcasestr(headers, "Cookie:");
	if (!p) return 0;
	p = strstr(p, "jwt=");
	if (!p) return 0;
	p += 4;
	const char* end = strpbrk(p, ";\r\n");
	size_t len = end ? (size_t)(end - p) : strlen(p);
	if (len == 0 || len + 1 > out_sz) return 0;
	memcpy(out, p, len);
	out[len] = '\0';
	return 1;
}

void http_send_jwt_redirect(SSL* ssl, const char* jwt, const char* location) {
	char response[1024];
	int n = snprintf(response, sizeof(response),
		"HTTP/1.1 302 Found\r\n"
		"Location: %s\r\n"
		"Set-Cookie: jwt=%s; HttpOnly; Secure; SameSite=Strict; Path=/\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n\r\n",
		location, jwt);
	if (n > 0) SSL_write(ssl, response, n);
}

// 1 - valid, 0 - not safe, -1 - expired, -2 - decode error
int decode_jwt(const char* jwt, s_jwt* claims) {
	if (!jwt || !claims) return -2;

	char header[128], b64_payload[256], signature[256];
	if (sscanf(jwt, "%127[^.].%255[^.].%255[^\n]", header, b64_payload, signature) != 3) return -2;

	if (!check_jwt((char*)jwt)) return 0;

	char std_b64[256];
	int b64_len = (int)strlen(b64_payload);
	unwrapper(b64_payload, b64_len, std_b64, (int)sizeof(std_b64));

	char json_buf[512];
	int json_len = d_b64(std_b64, json_buf, sizeof(json_buf) - 1);
	if (json_len <= 0)
		return -2;
	json_buf[json_len] = '\0';

	memset(claims, 0, sizeof(*claims));

	const char* p = strstr(json_buf, "\"uname\"");
	if (!p) return -2;
	p = strchr(p + 7, '"');
	if (!p) return -2;
	p++;
	const char* end = strchr(p, '"');
	if (!end) return -2;
	size_t uname_len = (size_t)(end - p);
	if (uname_len >= sizeof(claims->uname)) return -2;
	memcpy(claims->uname, p, uname_len);
	claims->uname[uname_len] = '\0';

	p = strstr(json_buf, "\"has_access\"");
	if (!p) return -2;
	p = strchr(p + 12, ':');
	if (!p) return -2;
	while (*p == ':' || *p == ' ') p++;
	claims->has_access = (*p == '1') ? 1 : 0;

	p = strstr(json_buf, "\"exp\"");
	if (!p) return -2;
	p = strchr(p + 5, ':');
	if (!p) return -2;
	while (*p == ':' || *p == ' ') p++;
	claims->exp = strtol(p, NULL, 10);

	if (claims->exp < (long)time(NULL)) return -1;

	return 1;
}

void http_send_access_denied(SSL* ssl) {
	const char* response =
		"HTTP/1.1 403 Forbidden\r\n"
		"Content-Type: text/plain\r\n"
		"Content-Length: 9\r\n"
		"Connection: close\r\n\r\n"
		"Forbidden";
	SSL_write(ssl, response, strlen(response));
}
