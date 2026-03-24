# Dependencies
- libsystemd-dev
- pdp (parsec)
- gssapi_krb5
- libldap-dev

# Compile
`gcc proxy.c sssd.c config.c http.c -o proxy -lpdp -lgssapi_krb5 -lcrypto -lsystemd`

# Setting up
- make sure kerberos tickets are up to date
- allow HTTP keytab to be used by whatever user is running the service (Identification -> Services -> HTTP -> ...)
- copy .ldif file to /etc/dirsrv/slapd-*/schema/ with chmod 660
- add "x-ald-user-mac" to /etc/sssd/sssd.conf under [domain/your.domain]
- also add user_attributes = +x-ald-user-mac under [ifp]
- `systemctl restart dirsrv@{domain here, check in /etc/systemd/system | grep dirsrv}.service && systemctl restart sssd`
- `ipa host-mod astraipa.domain.net --addattr=objectClass=x-ald-host-parsec`
- `ipa host-mod astraipa.domain.net --addattr=x-ald-host-mac="2:0x2:2:0x2"` (--setattr to change attribute)
- `ipa permission-add "Read host mac" --type=host --right={read,compare,search} --attrs=x-ald-host-mac --bindtype=all`
- `sudo execaps -c 0x00004 env KRB5_KTNAME=/var/lib/ipa/gssproxy/http.keytab ./proxy` or give user parsec privileges & run without execaps
