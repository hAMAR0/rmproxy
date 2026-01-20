# Dependencies
libcurl4-openssl-dev

jansson

pdp (parsec)

# Compile
gcc proxy.c config.c api.c -o proxy -lcurl -ljansson

# Setting up
sudo execaps -c 0x00004 ./proxy
