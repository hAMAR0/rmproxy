#include <string.h>
#include <systemd/sd-bus.h>
#include <ldap.h>
#include <time.h>
#include "sssd.h"
#include "config.h"

char* get_sssd_attr(const char* name, const char* attr_name) {
    sd_bus *bus = NULL;
    sd_bus_message *m = NULL, *reply = NULL;
    char *result = NULL;
    const char *attrs[] = {attr_name, NULL};

    if (sd_bus_open_system(&bus) < 0) return NULL;

    if (sd_bus_message_new_method_call(bus, &m,
                                       "org.freedesktop.sssd.infopipe",
                                       "/org/freedesktop/sssd/infopipe",
                                       "org.freedesktop.sssd.infopipe",
                                       "GetUserAttr") < 0) goto finish;

    sd_bus_message_append(m, "s", name);
    sd_bus_message_append_strv(m, (char **)attrs); 

    if (sd_bus_call(bus, m, 0, NULL, &reply) < 0) goto finish;

    if (sd_bus_message_enter_container(reply, 'a', "{sv}") < 0) goto finish;

    while (sd_bus_message_enter_container(reply, 'e', "sv") > 0) {
        const char *ret_attr_name;
        sd_bus_message_read(reply, "s", &ret_attr_name);

        if (strcmp(ret_attr_name, attr_name) == 0) {
            const char *attr_value;
            if (sd_bus_message_enter_container(reply, 'v', "as") >= 0 &&
                sd_bus_message_enter_container(reply, 'a', "s") >= 0 &&
                sd_bus_message_read(reply, "s", &attr_value) > 0) {
                
                result = strdup(attr_value);
            }
            break; 
        }
        sd_bus_message_skip(reply, "v");
        sd_bus_message_exit_container(reply);
    }

finish:
    sd_bus_message_unref(m);
    sd_bus_message_unref(reply);
    sd_bus_unref(bus);
    return result;
}


int sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in) {
    return LDAP_SUCCESS;
}

int ldap_get_host_mac(char* hostname, char* host_mac) {
	LDAP *ld;
	int n;
	int version = LDAP_VERSION3;
	char uri[128]; // = "ldap://astraipa.domain.net";
	const char *base_dn = "cn=computers,cn=accounts,dc=domain,dc=net";
	char filter[150]; // = "(fqdn=astraipa.domain.net)";
	LDAPMessage *result, *entry;
	char *attrs[] = {"x-ald-host-mac", NULL};
	struct berval **values;
	
	snprintf(uri, sizeof(uri), "ldap://%s", hostname);
	snprintf(filter, sizeof(filter), "(fqdn=%s)", hostname);

	n = ldap_initialize(&ld, uri);
	if (n != LDAP_SUCCESS) {
		printf("ldap_initialize error");
		return -1;
	}
	ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

	n = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL, NULL, LDAP_SASL_QUIET, sasl_interact, NULL);
	if (n != LDAP_SUCCESS) {
		printf("ldap_sasl_interactive_bins_s error");
		ldap_unbind_ext_s(ld, NULL, NULL);
		return -1;
	}

	n = ldap_search_ext_s(ld, base_dn, LDAP_SCOPE_SUBTREE, filter, attrs, 0, NULL, NULL, NULL, 0, &result);
	if (n != LDAP_SUCCESS) {
		printf("ldap_search_ext_s error");
		ldap_unbind_ext_s(ld, NULL, NULL);
		return -1;
	}

	for (entry = ldap_first_entry(ld, result); entry != NULL; entry = ldap_next_entry(ld, entry)) {
		values = ldap_get_values_len(ld, entry, "x-ald-host-mac");
		strcpy(host_mac, values[0]->bv_val);
		ldap_value_free_len(values);
	}
	ldap_msgfree(result);
	ldap_unbind_ext_s(ld, NULL, NULL);

	return 0;
}
