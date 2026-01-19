typedef struct {
	int port;
	int t_port;
	char *t_addr;
} pcfg;

int parse(const char *filename, pcfg* cfg);
