#pragma once

typedef struct {
	int port;
	int t_port;
	char *t_addr;
	char *dc_url;
} pcfg;

extern pcfg cfg;

int parse(const char *filename, pcfg* cfg);
