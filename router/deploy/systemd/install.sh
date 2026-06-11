#!/usr/bin/env bash
# Install the OpenScope router stack (router + console + migrate) on Linux.
# Usage: sudo ./install.sh [--upgrade]
# Expects the binaries + router.env.example next to this script (release tarball).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
UPGRADE=0
[[ "${1:-}" == "--upgrade" ]] && UPGRADE=1
[[ $(id -u) -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }

id -u openscope >/dev/null 2>&1 || useradd --system --home /var/lib/openscope --shell /usr/sbin/nologin openscope
mkdir -p /etc/openscope /var/lib/openscope
chown openscope:openscope /var/lib/openscope

for bin in openscope-router openscope-console openscope-mint openscope-migrate; do
    install -m 755 "$HERE/$bin" /usr/local/bin/$bin
done
[[ -f /etc/openscope/router.env ]] || { install -m 600 "$HERE/router.env.example" /etc/openscope/router.env; echo ">> wrote /etc/openscope/router.env — fill in DSNs + secrets before starting"; }
[[ -f "$HERE/dlp.example.yaml" ]] && install -m 644 "$HERE/dlp.example.yaml" /etc/openscope/dlp.example.yaml

install -m 644 "$HERE/openscope-router.service" "$HERE/openscope-console.service" /etc/systemd/system/
systemctl daemon-reload
if [[ $UPGRADE -eq 1 ]]; then
    systemctl restart openscope-router openscope-console
    echo ">> upgraded and restarted (migrations ran via ExecStartPre)"
else
    systemctl enable openscope-router openscope-console
    echo ">> installed. Edit /etc/openscope/router.env, then: systemctl start openscope-router openscope-console"
fi
