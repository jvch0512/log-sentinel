# log-sentinel

Go CLI that reads **SSH authentication logs** (`/var/log/auth.log`, `/var/log/secure`, journald exports) and reports who is attacking the host, with a focus on the finding that matters most: **a successful login right after failed attempts from the same address**.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Usage

```bash
go install github.com/jvch0512/log-sentinel@latest
log-sentinel /var/log/auth.log
journalctl -u ssh --no-pager | log-sentinel -
log-sentinel -window 5m -brute 8 -spray 4 -allow 10.0.0.5,203.0.113.10 /var/log/auth.log
log-sentinel -json auth.log          # exit code 2 when anything is detected
```

```
[CRITICAL] success_after_failures  203.0.113.9   6 events  Nov 12 10:00:00 -> 10:02:00
    successful password login for 'deploy' right after failed attempts ...
```
(illustrative output)

## Detections

| Type | Severity | Rule |
|------|----------|------|
| `success_after_failures` | critical | accepted login from an address that just failed several times (possible compromised credential) |
| `brute_force` | high | `-brute` failures from one IP inside the sliding `-window` |
| `password_spraying` | high | `-spray` distinct usernames from one IP inside the window |

## Details worth knowing

* Parses classic syslog stamps (no year, so `-year` is applied and a December to January rollover is detected) and RFC 3339 stamps
* IPv4 and IPv6 sources; "Failed password", "invalid user", "Invalid user" and "Accepted" lines
* Sliding window per address, so slow attempts spread over hours do not trip the burst rule (tested)
* Allow-list for your own jump hosts and monitoring
* Output sorted by severity, then volume
* Reads logs only; it never blocks anything. Feed the IPs to your firewall or fail2ban yourself

## Development

```bash
go vet ./... && go test -race ./...
```

MIT licensed.
