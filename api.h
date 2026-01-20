#pragma once
#include <parsec/parsec_mac.h>
#include <stdint.h>
#include <string.h>
#include <parsec/parsec.h>

typedef struct {
        parsec_lev_t min_lvl, max_lvl;
        parsec_cat_t min_cat, max_cat;
} Labels;

size_t get_response(void *ptr, size_t size, size_t nmemb, char *userp);

Labels get_mac_label(char *buffer);

int get_labels(Labels *mac_labels);
