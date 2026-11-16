#!/bin/sh
# mango-swap.sh - install /root/tailscaled.mc as /usr/sbin/tailscaled on the GL-MG1300 with automatic rollback.
# Runs detached (Tailscale is stopped briefly). Usage on the router:
#   start-stop-daemon -S -b -m -p /tmp/mc-swap.pid -x /root/mango-swap.sh -- --child <peer-ip> [<peer-ip>...]
# <peer-ip>: Tailscale IPs of peers to ping after the swap (any pong = OK; otherwise roll back).
# Log: /root/mango-swap.log. Rollback copy: /root/tailscaled.prev (delete after you're happy).
BIN=/usr/sbin/tailscaled NEW=/root/tailscaled.mc PREV=/root/tailscaled.prev LOG=/root/mango-swap.log
log() { echo "$(date '+%F %T') $*" >> "$LOG"; }
[ "$1" = "--child" ] || { echo "run via start-stop-daemon (see header)"; exit 1; }
shift; PING_TARGETS="$*"
[ -n "$PING_TARGETS" ] || { log "ABORT: no peer IPs given"; exit 1; }
[ -s "$NEW" ] || { log "ABORT: $NEW missing"; exit 1; }
log "=== swap: installed $($BIN --version | head -1), new $($NEW --version 2>/dev/null | head -1)"
/etc/init.d/tailscale stop; sleep 2
mv -f $BIN $PREV && mv -f $NEW $BIN && chmod 755 $BIN || { log "mv failed"; [ -s $PREV ] && mv -f $PREV $BIN; /etc/init.d/tailscale start; exit 1; }
/etc/init.d/tailscale start
ok=0
for i in $(seq 1 24); do sleep 5
  for t in $PING_TARGETS; do tailscale ping -c 1 --timeout 4s $t 2>/dev/null | grep -q pong && { ok=1; break 2; }; done
done
if [ $ok = 1 ]; then log "OK after $((i*5)) s: running $($BIN --version | head -1); MemAvailable $(awk '/MemAvailable/{print $2}' /proc/meminfo) kB"
else log "FAIL: no pong in 120 s - rolling back"; /etc/init.d/tailscale stop; sleep 2; mv -f $PREV $BIN; /etc/init.d/tailscale start; log "rolled back to $($BIN --version | head -1)"; fi
log "=== done"
