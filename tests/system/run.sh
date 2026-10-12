#!/usr/bin/env bash
# Run the system tests and benchmarks against a real OpenVPN + OpenLDAP in Docker.
# Usage: tests/system/run.sh [python_version] [openvpn_version] [pytest args...]
set -euo pipefail

export python_version="${1:-3.14}" openvpn_version="${2:-2.6}"
shift $(($# < 2 ? $# : 2))
export COMPOSE_PROJECT_NAME="openvpn-ldap-auth-py${python_version//./}-ovpn${openvpn_version//./}"

compose=(docker compose -f "$(dirname "$0")/resources/docker/docker-compose.yml")
trap '"${compose[@]}" down' EXIT

"${compose[@]}" up -d --build
# Installs the package non-editable (exercises the real build), builds the PyInstaller binary,
# then hands ownership of everything written into the bind mount back to the caller.
"${compose[@]}" run --rm openvpn bash -euo pipefail -c '
  trap "chown -R '"$(id -u):$(id -g)"' /project/benchmark 2>/dev/null || true" EXIT
  openvpn --version | head -1
  uv sync --frozen --no-editable
  pyinstaller --onefile --name openvpn-ldap-auth-pyinstaller --distpath /usr/local/bin \
    --workpath /tmp/pyinstaller --specpath /tmp/pyinstaller openvpn_ldap_auth/main.py
  pytest -p no:cacheprovider tests/system "$@"
' bash "$@"
