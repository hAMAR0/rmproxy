# Dependencies
libcurl4-openssl-dev

jansson

pdp (parsec)

gssapi_krb5

# Compile
gcc proxy.c api.c config.c -o proxy -lcurl -ljansson -lpdp -lgssapi_krb5

# Setting up
sudo execaps -c 0x00004 ./proxy
