# Dependencies
libcurl4-openssl-dev

jansson

pdp (parsec)

gssapi_krb5

# Compile
gcc proxy.c api.c http.c config.c -o proxy -lpdp -lgssapi_krb5 -ljansson -lcurl -lcrypto

# Setting up
- make sure kerberos tickets are up to date
- sudo ipa-getkeytab -s astraipa.domain.net -p HTTP/astraipa.domain.net@DOMAIN.NET -k /etc/rmp_proxy.keytab
- sudo execaps -c 0x00004 ./proxy
