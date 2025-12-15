set -e

if [ -s /certs/ca-certificate.crt ]; then
  mkdir -p /usr/local/share/ca-certificates
  cp /certs/ca-certificate.crt /usr/local/share/ca-certificates/extra-ca.crt
  update-ca-certificates >/dev/null 2>&1 || true
fi

supervisord -c ./aria2.supervisor.conf
exec ./cloudreve
