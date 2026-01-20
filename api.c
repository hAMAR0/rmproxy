#include <curl/curl.h>
#include <string.h>
#include <jansson.h>
#include <stdint.h>
#include "config.h"
#include "api.h"


size_t get_response(void *ptr, size_t size, size_t nmemb, char *userp) {
	size_t rsize = size * nmemb;
	strncat(userp, (char *)ptr, rsize);
	return rsize;
}

Labels get_mac_label(char *buffer) {
	Labels mac_label = {0};

	json_error_t error;
	json_t *root = json_loads(buffer, 0, &error);

	json_t *res1 = json_object_get(root, "result");
	json_t *res2 = json_object_get(res1, "result");

	json_t *mac = json_object_get(res2, "x-ald-user-mac");

	json_t *mac_str_obj = json_array_get(mac, 0);
	const char *mac_str = json_string_value(mac_str_obj);

	
	sscanf(mac_str, "%hhd:%llx:%hhd:%llx", &mac_label.min_lvl, &mac_label.min_cat, &mac_label.max_lvl, mac_label.max_cat);

	json_decref(root);
	return mac_label;
}


int get_labels(Labels *mac_labels) {
	parse("./mrp.conf", &cfg);

	char url[512]; 
	snprintf(url, sizeof(url), "%s/ipa/json", cfg.dc_url);
	
	char buffer[8192] = {0};

	CURL *curl = curl_easy_init();

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, get_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);
	
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_GSSNEGOTIATE);
	curl_easy_setopt(curl, CURLOPT_USERPWD, ":");
	
	char  *json_payload = "{\"method\": \"user_show\", \"params\": [[\"administrator\"], {\"all\": true}], \"id\": 0}";

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);

	char url2[512];
	snprintf(url2, sizeof(url2), "Referer: %s/ipa", cfg.dc_url);

	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, url2);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ipa/ca.crt");

	CURLcode res = curl_easy_perform(curl);

	if (res == CURLE_OK) printf("%s\n", buffer);
	else printf("%s\n", curl_easy_strerror(res));

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	
	Labels tlabel = get_mac_label(buffer);
	mac_labels->max_cat = tlabel.max_cat;
	mac_labels->max_lvl = tlabel.max_lvl;
	mac_labels->min_cat = tlabel.min_cat;
	mac_labels->min_lvl = tlabel.min_lvl;
	
	return 0;
}
