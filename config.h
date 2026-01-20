#pragma once

typedef struct {
	int port;
	int t_port;
	char *t_addr;
	char *dc_url;
} pcfg;

int parse(const char *filename, pcfg* cfg);
