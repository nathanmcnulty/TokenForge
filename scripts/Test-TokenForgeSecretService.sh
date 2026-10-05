#!/usr/bin/env bash
# Run inside dbus-run-session. All passwords and keyring files are disposable synthetic fixtures.
set -euo pipefail
ulimit -c 0
unset DISPLAY WAYLAND_DISPLAY
fixture=$(mktemp -d)
export XDG_DATA_HOME="$fixture/data"
export XDG_RUNTIME_DIR="$fixture/runtime"
mkdir -m 700 "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"
keyring_pid=''
cleanup() { if [[ -n "$keyring_pid" ]]; then kill "$keyring_pid" 2>/dev/null || true; wait "$keyring_pid" 2>/dev/null || true; fi; rm -rf "$fixture"; }
trap cleanup EXIT
python3 -c 'import secrets; print(secrets.token_urlsafe(32), end="")' | gnome-keyring-daemon --unlock --foreground --components=secrets >/dev/null 2>/dev/null &
keyring_pid=$!
# Wait for the test bus service, without reading or logging any password.
for attempt in {1..100}; do
 if dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner string:org.freedesktop.secrets | grep -q 'boolean true'; then break; fi
 sleep 0.1
done
if ! dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner string:org.freedesktop.secrets | grep -q 'boolean true'; then
 echo 'Synthetic Secret Service did not start.' >&2
 exit 1
fi
"$@"
