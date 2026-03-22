#include <string.h>
#include <systemd/sd-bus.h>
#include "sssd.h"

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

