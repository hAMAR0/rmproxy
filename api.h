#pragma once
#include <stdint.h>
#include <string.h>

typedef struct {
        uint8_t min_lvl, max_lvl;
        uint64_t min_cat, max_cat;
} Labels;

size_t get_response(void *ptr, size_t size, size_t nmemb, char *userp);

Labels get_mac_label(char *buffer);

int get_labels(Labels *mac_labels);
