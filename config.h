#pragma once

typedef struct {
	int port;
	int t_port;
	char *t_addr;
	char *dc_url;
	char *cert_path;
} pcfg;

extern pcfg cfg;

int parse(const char *filename, pcfg* cfg);
