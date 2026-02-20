#include <string.h>

int http_read_header(int fd, char* buf, size_t buf_size, size_t* output_len);
int http_send_401(int fd, const char* b64tok);
int http_extract_negotiate_token(const char* headers, size_t headers_len, char* out_tok, size_t out_tok_sz);

	int d_b64(const char* input, char* out, size_t out_sz);
int e_b64(const void* input, int input_len, char* out, size_t out_sz);
