#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(uname -m)" = x86_64
directory="$(mktemp -d "${RUNNER_TEMP:?}/tokenforge-age.XXXXXXXX")"
archive="$directory/age.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-time 45 --max-filesize 19405817 --output "$archive" \
  https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz
printf '%s  %s\n' cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10 "$archive" |
  sha256sum --check --status
tar -xzf "$archive" -C "$directory" --no-same-owner --no-same-permissions age/age
test "$("$directory/age/age" --version)" = v1.3.2
printf '%s\n' "$directory/age" >> "${GITHUB_PATH:?}"
