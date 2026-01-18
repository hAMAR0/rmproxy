#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

#define CONF_BUF_LEN 128

// .conf file structure:
// name1 = value
// name2 = value2

char* trim(char *str) {
	char *end;
	while(isspace((unsigned char)*str)) str++;
	end = str + strlen(str) - 1;
	while(end > str && isspace((unsigned char)*end)) end--;
	end[1] = '\0';
	return str;
}

int parse(const char *filename, pcfg* cfg) {
	char buffer[CONF_BUF_LEN];
	FILE *pf = fopen(filename, "r");

	while(fgets(buffer, sizeof(buffer), pf)) {
		char *name;
		char *value;
		char *delimeter = strchr(buffer, '=');

		if (delimeter) {
			*delimeter = '\0';
			name = trim(buffer);
			value = trim(delimeter+1);

			if (strcmp(name, "port") == 0) cfg->port = atoi(value);
		}
	}

	fclose(pf);
	return 0;
}
