set -e

CERT_SRC="/certs/ca-certificate.crt"
if [ -f "$CERT_SRC" ] && [ -s "$CERT_SRC" ]; then
  mkdir -p /usr/local/share/ca-certificates
  cp "$CERT_SRC" /usr/local/share/ca-certificates/extra-ca.crt
  update-ca-certificates >/dev/null 2>&1 || true
else
  echo "[Info] Custom CA not found (or not a file): $CERT_SRC" >&2
fi

supervisord -c ./aria2.supervisor.conf
exec ./cloudreve
