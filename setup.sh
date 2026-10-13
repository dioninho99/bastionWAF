#!/usr/bin/env bash
# Guided Docker installation; run from any directory with: bash /path/to/setup.sh
set -euo pipefail
# Never expose credentials through inherited shell tracing.
set +x
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

case "${1:-}" in
  '') reset=false ;;
  --reset-password) reset=true ;;
  --help|-h) printf 'Usage: bash setup.sh [--reset-password]\n'; exit 0 ;;
  *) printf 'Unknown option. Use --help.\n' >&2; exit 1 ;;
esac
[[ -t 0 && -t 1 ]] || { echo 'Run this wizard in an interactive terminal.' >&2; exit 1; }
for command in docker openssl; do
  command -v "$command" >/dev/null || { echo "Install $command before running setup." >&2; exit 1; }
done
docker compose version >/dev/null
docker info >/dev/null

echo 'Bastion WAF setup'
echo 'Existing configuration and data are preserved.'
if [[ "$reset" == true && ! -f secrets/admin_password.txt ]]; then
  echo 'No administrator password exists yet. Run bash setup.sh first.' >&2
  exit 1
fi
if [[ ! -f .env ]]; then
  if [[ "$reset" == true ]]; then
    echo 'Missing .env. Run bash setup.sh first.' >&2
    exit 1
  fi
  echo
  echo 'Admin access defaults to an SSH tunnel (127.0.0.1:9090).'
  read -r -p 'Allow backends on your private network? [y/N] ' private
  case "$private" in y|Y|yes|YES) private=true ;; *) private=false ;; esac
  cp .env.example .env
  # Only change the fresh example, never an existing deployment configuration.
  if [[ "$private" == true ]]; then
    env_tmp=$(mktemp .env.XXXXXX)
    sed 's/^BASTION_ALLOW_PRIVATE_UPSTREAMS=false$/BASTION_ALLOW_PRIVATE_UPSTREAMS=true/' .env > "$env_tmp"
    mv "$env_tmp" .env
  fi
fi
mkdir -p secrets certs geoip
chmod 700 secrets

generated=false
secret_tmp=''
trap '[[ -z "$secret_tmp" ]] || rm -f -- "$secret_tmp"' EXIT
if [[ ! -f secrets/admin_password.txt || "$reset" == true ]]; then
  echo
  echo 'Choose a passphrase of at least 20 characters (several words work well).'
  echo 'Leave empty to generate a password.'
  while true; do
    read -r -s -p 'Admin password: ' password
    echo
    if [[ -z "$password" ]]; then
      password=$(openssl rand -hex 16)
      generated=true
      break
    fi
    if [[ ${#password} -lt 20 || "$password" =~ ^[[:space:]] || "$password" =~ [[:space:]]$ ]]; then
      echo 'Use at least 20 characters, without leading or trailing whitespace.'
      continue
    fi
    read -r -s -p 'Repeat password: ' confirmation
    echo
    [[ "$password" == "$confirmation" ]] && break
    echo 'Passwords do not match. Try again.'
  done
  secret_tmp=$(mktemp secrets/.admin-password.XXXXXX)
  printf '%s\n' "$password" > "$secret_tmp"
  chmod 400 "$secret_tmp"
  if [[ "$EUID" -eq 0 ]]; then
    chown 10001:10001 "$secret_tmp"
  else
    echo 'Container file ownership requires sudo once.'
    sudo chown 10001:10001 "$secret_tmp"
  fi
  mv -f -- "$secret_tmp" secrets/admin_password.txt
  secret_tmp=''
  if [[ "$generated" == true ]]; then
    printf '\nYour admin password: %s\nSave it in your password manager.\n' "$password"
  fi
  unset password confirmation
fi

echo
echo 'Building and starting Bastion; the first build can take several minutes.'
# Recreate to remount an atomically replaced secret and invalidate old sessions.
docker compose up -d --build --force-recreate --wait --wait-timeout 120 bastion
echo
echo 'Bastion is ready.'
echo 'On your workstation: ssh -L 9090:127.0.0.1:9090 your-user@LXC-IP'
echo 'Open http://localhost:9090 (or your existing configured admin URL).'
echo 'Sign in with your admin password; leave Username empty.'
echo 'Next: Proxy Hosts → Add proxy host. Certificates can be configured in the UI.'
echo 'Password recovery: bash setup.sh --reset-password'
