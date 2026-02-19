int http_read_header(int fd, char* dest_token); 
int get_token(char* buf, char* ktoken);
int send_response(int fd);
int d_b64(const char* input, char* out);
