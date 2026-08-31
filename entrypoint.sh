#!/bin/sh
# Dev-only tailnet access. When TS_AUTHKEY is injected (dev tracks only), join the tailnet so an
# operator can reach this grader for live iteration; learner tracks never set it, so no daemon runs
# and no surface is exposed. Presence of the key is the switch. Never `set -e`: the grader must
# reach its keepalive even if the mesh fails to come up.
if [ -n "${TS_AUTHKEY:-}" ]; then
  # No TUN device in a container -> userspace networking. Ephemeral state: a fresh node per boot is
  # correct for a throwaway dev lease.
  tailscaled --tun=userspace-networking --state=mem: --socks5-server=localhost:1055 \
    >/var/log/tailscaled.log 2>&1 &
  i=0
  while [ ! -S /var/run/tailscale/tailscaled.sock ] && [ "$i" -lt 10 ]; do i=$((i + 1)); sleep 1; done
  tailscale up --authkey "$TS_AUTHKEY" --hostname "${TS_HOSTNAME:-grader-dev}" --ssh \
    || echo "tailscale up failed (see /var/log/tailscaled.log)" >&2
fi

exec "$@"
