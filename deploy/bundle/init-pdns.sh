#!/bin/sh
# One-shot (pdns-init): the PowerDNS API keys and the API include files.
# A key is generated on this host once and kept on every later start; dns
# reads it by reference (file:/secrets/...). Both APIs listen on the compose
# network only. dns (uid 10001) owns the include directories it renders
# 50-freya.* into; PowerDNS (uid/gid 953) reads them through the group.
set -eu
umask 077
for k in pdns-auth pdns-recursor; do
  if [ ! -s "/secrets/$k.key" ]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "/secrets/$k.key"
    echo "$k API key generated"
  fi
done
AUTH=$(cat /secrets/pdns-auth.key)
REC=$(cat /secrets/pdns-recursor.key)
printf '%s\n' '# Written by pdns-init. API on the internal network only.' \
  'webserver=yes' 'api=yes' "api-key=$AUTH" 'webserver-address=0.0.0.0' 'webserver-port=8081' \
  'webserver-allow-from=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16' > /auth-conf/00-api.conf
printf '%s\n' '# Written by pdns-init. API on the internal network only.' \
  'webservice:' '  webserver: true' '  address: 0.0.0.0' '  port: 8082' "  api_key: \"$REC\"" \
  '  api_dir: /var/lib/pdns-recursor-api' \
  '  allow_from: ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]' > /recursor-conf/00-api.yml
chown 953:953 /auth-conf/00-api.conf /recursor-conf/00-api.yml /recursor-api
chmod 0600 /auth-conf/00-api.conf /recursor-conf/00-api.yml
chown 10001:953 /auth-conf /recursor-conf
chmod 0750 /auth-conf /recursor-conf
chown 10001:10001 /secrets/pdns-auth.key /secrets/pdns-recursor.key /state
chmod 0400 /secrets/pdns-auth.key /secrets/pdns-recursor.key
chmod 0700 /state
echo "PowerDNS API keys and include files ready"
