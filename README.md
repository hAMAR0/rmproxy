# Dependencies
- libcurl4-openssl-dev
- libsystemd-dev
- jansson
- pdp (parsec)
- gssapi_krb5

# Compile
gcc proxy.c sssd.c config.c http.c -o proxy -lpdp -lgssapi_krb5 -lcrypto -lsystemd

# Setting up
- make sure kerberos tickets are up to date
- allow HTTP keytab to be used by whatever user is running the service (Identification -> Services -> HTTP -> ...)
- sudo execaps -c 0x00004 env KRB5_KTNAME=/var/lib/ipa/gssproxy/http.keytab ./proxy
