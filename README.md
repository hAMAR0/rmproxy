# Обратный прокси сервер с поддержкой мандатного управления доступом на Astra Linux.

## Зависимости
- libsystemd-dev
- parsec-dev
- libkrb5-dev
- libldap-dev
- libssl-dev

## Компиляция
`gcc proxy.c sssd.c config.c http.c -o proxy -lpdp -lgssapi_krb5 -lcrypto -lsystemd -lldap -lssl`

## Настройка
- Сгенерируйте самоподписанные сертификаты и поместите их в папку ./cert: `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=localhost"`
- Убедитесь, что Kerberos-билеты актуальны
- Разрешите использование HTTP keytab для пользователя, под которым запускается сервис (Identification -> Services -> HTTP -> ...)
- Скопируйте .ldif файл в /etc/dirsrv/slapd-*/schema/ с `chmod 660`
- Добавьте "x-ald-user-mac" в /etc/sssd/sssd.conf в раздел [domain/your.domain]
- Также добавьте user_attributes = +x-ald-user-mac в раздел [ifp]
- `systemctl restart dirsrv@{domain здесь, проверьте в /etc/systemd/system | grep dirsrv}.service && systemctl restart sssd`
- `ipa host-mod astraipa.domain.net --addattr=objectClass=x-ald-host-parsec`
- `ipa host-mod astraipa.domain.net --addattr=x-ald-host-mac="2:0x2:2:0x2"` (--setattr для изменения атрибута)
- `ipa permission-add "Read host mac" --type=host --right={read,compare,search} --attrs=x-ald-host-mac --bindtype=all`
- `sudo execaps -c 0x00004 env KRB5_KTNAME=/var/lib/ipa/gssproxy/http.keytab ./proxy` или дайте пользователю привилегии parsec и запустите без execaps

---

# A reverse proxy with mandatory access control support (MAC) for Astra Linux

## Dependencies
- libsystemd-dev
- parsec-dev
- libkrb5-dev
- libldap-dev
- libssl-dev

## Compile
`gcc proxy.c sssd.c config.c http.c -o proxy -lpdp -lgssapi_krb5 -lcrypto -lsystemd -lldap -lssl`

## Setting up 
- Generate self-signed certificates and place them in ./cert directory: `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=localhost"`
- Make sure kerberos tickets are up to date
- Allow HTTP keytab to be used by whatever user is running the service (Identification -> Services -> HTTP -> ...)
- Copy .ldif file to /etc/dirsrv/slapd-*/schema/ with `chmod 660`
- Add "x-ald-user-mac" to /etc/sssd/sssd.conf under [domain/your.domain]
- Also add user_attributes = +x-ald-user-mac under [ifp]
- `systemctl restart dirsrv@{domain here, check in /etc/systemd/system | grep dirsrv}.service && systemctl restart sssd`
- `ipa host-mod astraipa.domain.net --addattr=objectClass=x-ald-host-parsec`
- `ipa host-mod astraipa.domain.net --addattr=x-ald-host-mac="2:0x2:2:0x2"` (--setattr to change attribute)
- `ipa permission-add "Read host mac" --type=host --right={read,compare,search} --attrs=x-ald-host-mac --bindtype=all`
- `sudo execaps -c 0x00004 env KRB5_KTNAME=/var/lib/ipa/gssproxy/http.keytab ./proxy` or give user parsec privileges & run without execaps
