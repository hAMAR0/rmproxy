#include <curl/curl.h>
#include <curl/easy.h>
#include <string.h>
#include "config.h"


pcfg cfg;

int main() {
	parse("./mrp.conf", &cfg);

	char *url = cfg.dc_url;
	strcat(url, "/api/json");
	
	CURL *curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_GSSNEGOTIATE);
	curl_easy_setopt(curl, CURLOPT_USERPWD, ":");
	
	char  *json_payload = "{\"method\": \"user_show\", \"params\": [[\"administrator\"], {\"all\": true}], \"id\": 0}";

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);

	struct curl_slist *headers = NULL;
	char *url2 = "Referer: ";
	strcat(url2, cfg.dc_url);
	strcat(url2, "/api");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, url2);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ipa/ca.crt");

	CURLcode res = curl_easy_perform(curl);

	if (res == CURLE_OK) printf("ok gj");

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
}
