#!/usr/bin/env bash
# Start a disposable local OpenSSH server for russh e2e (password + sftp + PTY).
set -euo pipefail
ROOT="${HARBOR_E2E_SSH_DIR:-/tmp/harbor-e2e-sshd}"
PORT="${HARBOR_E2E_SSH_PORT:-22222}"
USER_NAME="${HARBOR_E2E_SSH_USER:-harbor-e2e}"
PASSWORD="${HARBOR_E2E_SSH_PASSWORD:-HarborE2e!test}"
HOST="${HARBOR_E2E_SSH_HOST:-127.0.0.1}"

mkdir -p "$ROOT"
if [[ ! -f "$ROOT/host" ]]; then
  ssh-keygen -t ed25519 -f "$ROOT/host" -N '' -q
fi

if [[ ! -x /usr/sbin/sshd ]]; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server
fi

if ! id "$USER_NAME" >/dev/null 2>&1; then
  sudo useradd -m -s /bin/bash "$USER_NAME"
fi
echo "${USER_NAME}:${PASSWORD}" | sudo chpasswd

cat > "$ROOT/sshd_config" <<EOF
Port ${PORT}
ListenAddress ${HOST}
HostKey ${ROOT}/host
PidFile ${ROOT}/sshd.pid
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication no
PermitRootLogin no
StrictModes no
PrintMotd no
Subsystem sftp internal-sftp
AcceptEnv LANG LC_*
EOF

if [[ -f "$ROOT/sshd.pid" ]] && sudo kill -0 "$(cat "$ROOT/sshd.pid")" 2>/dev/null; then
  echo "sshd already running pid=$(cat "$ROOT/sshd.pid")"
else
  sudo /usr/sbin/sshd -f "$ROOT/sshd_config" -E "$ROOT/sshd.log"
fi

for _ in $(seq 1 50); do
  if bash -c "echo >/dev/tcp/${HOST}/${PORT}" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

export HARBOR_E2E_SSH_PORT="$PORT"
export HARBOR_E2E_SSH_USER="$USER_NAME"
export HARBOR_E2E_SSH_PASSWORD="$PASSWORD"
export HARBOR_E2E_SSH_HOST="$HOST"
echo "e2e sshd ${HOST}:${PORT} user=${USER_NAME}"
if [[ "${1:-}" == "test" ]]; then
  shift
  extra=("${@}")
  if [[ ${#extra[@]} -eq 0 ]]; then
    extra=(--include-ignored)
  fi
  cargo test --all-targets --locked --offline -- --test-threads=1 "${extra[@]}"
fi
