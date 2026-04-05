#include <string.h>
#include <openssl/ssl.h>

int http_read_header(SSL *ssl, char* buf, size_t buf_size, size_t* output_len);
int http_send_401(SSL *ssl, const char* b64tok);
int http_extract_negotiate_token(const char* headers, size_t headers_len, char* out_tok, size_t out_tok_sz);
int http_get_host(const char *headers, char *out, size_t max_len);
int d_b64(const char* input, char* out, size_t out_sz);
int e_b64(const void* input, int input_len, char* out, size_t out_sz);
int create_jwt(char* payload, char* jwt);
int check_jwt(char* jwt);
