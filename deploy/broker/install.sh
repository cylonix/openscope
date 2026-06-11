#!/usr/bin/env bash
# Install the OpenScope broker (openscoped) on a Linux VPC host.
#
# Usage:
#   sudo ./install.sh [--upgrade]
#
# Expects openscoped + openscope binaries next to this script (e.g. from a
# release tarball, or built with:
#   CGO_ENABLED=0 GOOS=linux go build ./cmd/openscoped ./cmd/openscope ).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
UPGRADE=0
[[ "${1:-}" == "--upgrade" ]] && UPGRADE=1

if [[ $(id -u) -ne 0 ]]; then
    echo "run as root (sudo)" >&2
    exit 1
fi

# User + directories
id -u openscope >/dev/null 2>&1 || useradd --system --home /var/lib/openscope --shell /usr/sbin/nologin openscope
mkdir -p /etc/openscope /var/lib/openscope
chown openscope:openscope /var/lib/openscope
chmod 700 /var/lib/openscope

# Binaries
install -m 755 "$HERE/openscoped" /usr/local/bin/openscoped
install -m 755 "$HERE/openscope" /usr/local/bin/openscope

# Config (never overwrite an existing env file)
if [[ ! -f /etc/openscope/openscoped.env ]]; then
    install -m 600 "$HERE/openscoped.env.example" /etc/openscope/openscoped.env
    echo ">> wrote /etc/openscope/openscoped.env — review it before starting"
fi

# systemd + logrotate
install -m 644 "$HERE/openscoped.service" /etc/systemd/system/openscoped.service
[[ -d /etc/logrotate.d ]] && install -m 644 "$HERE/logrotate.openscope" /etc/logrotate.d/openscope

systemctl daemon-reload
if [[ $UPGRADE -eq 1 ]]; then
    systemctl restart openscoped
    echo ">> upgraded and restarted openscoped"
else
    systemctl enable openscoped
    cat <<'EOF'
>> installed. Next steps:
   1. Edit /etc/openscope/openscoped.env (TLS cert/key or PLAINTEXT_OK for proxy termination)
   2. Add admin configs: /etc/openscope/ssh_targets.yaml, http_profiles.yaml, system_commands.yaml
   3. systemctl start openscoped
   4. Mint agent tokens:
        sudo -u openscope OPENSCOPE_CONFIG_DIR=/var/lib/openscope openscope agent token mint <agent_id>
   5. Back up /var/lib/openscope/token_pepper — losing it invalidates all tokens
EOF
fi
