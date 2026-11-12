package sentinel

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func burst(ip string, start time.Time, n int, userFn func(i int) string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		t := start.Add(time.Duration(i) * 10 * time.Second)
		fmt.Fprintf(&b, "%s host sshd[%d]: Failed password for %s from %s port %d ssh2\n", t.Format("Jan _2 15:04:05"), 1000+i, userFn(i), ip, 40000+i)
	}
	return b.String()
}

var t0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func parse(t *testing.T, s string) []Event {
	t.Helper()
	ev, err := Parse(strings.NewReader(s), 2026, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestParseVariants(t *testing.T) {
	log := `Nov 12 10:00:01 h sshd[1]: Failed password for root from 203.0.113.5 port 5555 ssh2
Nov 12 10:00:02 h sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 5556 ssh2
Nov 12 10:00:03 h sshd[1]: Invalid user oracle from 2001:db8::1 port 22
Nov 12 10:00:04 h sshd[1]: Accepted publickey for deploy from 198.51.100.7 port 6000 ssh2: RSA SHA256:abc
2026-11-12T10:00:05.123456+00:00 h sshd[1]: Failed password for bob from 192.0.2.9 port 22 ssh2
Nov 12 10:00:06 h cron[2]: (root) CMD (run-parts /etc/cron.hourly)
garbage line with no timestamp
`
	ev := parse(t, log)
	if len(ev) != 5 {
		t.Fatalf("want 5 events, got %d: %+v", len(ev), ev)
	}
	if ev[1].User != "admin" || ev[1].Kind != Failed || ev[2].IP != "2001:db8::1" || ev[2].Kind != Invalid {
		t.Fatalf("fields wrong: %+v", ev)
	}
	if ev[3].Kind != Accepted || ev[3].Method != "publickey" || ev[3].User != "deploy" {
		t.Fatalf("accepted wrong: %+v", ev[3])
	}
	if ev[4].Time.Year() != 2026 || ev[4].Time.Second() != 5 {
		t.Fatalf("iso time wrong: %v", ev[4].Time)
	}
}

func TestYearRolloverInSyslog(t *testing.T) {
	log := "Dec 31 23:59:00 h sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2\nJan  1 00:00:10 h sshd[1]: Failed password for a from 192.0.2.1 port 2 ssh2\n"
	ev, _ := Parse(strings.NewReader(log), 2025, time.UTC)
	if len(ev) != 2 || ev[1].Time.Year() != 2026 {
		t.Fatalf("rollover not handled: %+v", ev)
	}
}

func TestBruteForceThreshold(t *testing.T) {
	ev := parse(t, burst("203.0.113.5", t0, 12, func(int) string { return "root" }))
	a := Detect(ev, DefaultConfig())
	if len(a) != 1 || a[0].Type != "brute_force" || a[0].Count < 10 || a[0].IP != "203.0.113.5" {
		t.Fatalf("got %+v", a)
	}
	if got := Detect(parse(t, burst("203.0.113.5", t0, 9, func(int) string { return "root" })), DefaultConfig()); len(got) != 0 {
		t.Fatalf("below threshold should be quiet: %+v", got)
	}
}

func TestSlowAttackOutsideWindowIsNotBruteForce(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 12; i++ {
		b.WriteString(burst("203.0.113.5", t0.Add(time.Duration(i)*30*time.Minute), 1, func(int) string { return "root" }))
	}
	if got := Detect(parse(t, b.String()), DefaultConfig()); len(got) != 0 {
		t.Fatalf("spread attempts should not trip the burst rule: %+v", got)
	}
}

func TestPasswordSprayingListsUsers(t *testing.T) {
	names := []string{"admin", "root", "ubuntu", "oracle", "test", "postgres"}
	ev := parse(t, burst("198.51.100.20", t0, 6, func(i int) string { return names[i] }))
	a := Detect(ev, DefaultConfig())
	if len(a) != 1 || a[0].Type != "password_spraying" || len(a[0].Users) != 6 {
		t.Fatalf("got %+v", a)
	}
}

func TestSuccessAfterFailuresIsCritical(t *testing.T) {
	log := burst("203.0.113.9", t0, 6, func(int) string { return "deploy" }) +
		t0.Add(2*time.Minute).Format("Jan _2 15:04:05") + " h sshd[9]: Accepted password for deploy from 203.0.113.9 port 7000 ssh2\n"
	a := Detect(parse(t, log), DefaultConfig())
	if len(a) == 0 || a[0].Severity != "critical" || a[0].Type != "success_after_failures" {
		t.Fatalf("got %+v", a)
	}
}

func TestLegitimateLoginIsQuietAndAllowListWorks(t *testing.T) {
	ok := t0.Format("Jan _2 15:04:05") + " h sshd[9]: Accepted publickey for alice from 198.51.100.7 port 7000 ssh2\n"
	if got := Detect(parse(t, ok), DefaultConfig()); len(got) != 0 {
		t.Fatalf("clean login produced alerts: %+v", got)
	}
	cfg := DefaultConfig()
	cfg.Allow["203.0.113.5"] = true
	if got := Detect(parse(t, burst("203.0.113.5", t0, 30, func(int) string { return "root" })), cfg); len(got) != 0 {
		t.Fatalf("allow-listed IP alerted: %+v", got)
	}
}

func TestAlertsSortedBySeverityThenVolume(t *testing.T) {
	log := burst("192.0.2.1", t0, 11, func(int) string { return "root" }) + burst("192.0.2.2", t0, 40, func(int) string { return "root" }) +
		burst("192.0.2.3", t0, 6, func(int) string { return "x" }) + t0.Add(time.Minute).Format("Jan _2 15:04:05") + " h sshd[9]: Accepted password for x from 192.0.2.3 port 1 ssh2\n"
	a := Detect(parse(t, log), DefaultConfig())
	if len(a) < 3 || a[0].Severity != "critical" || a[1].IP != "192.0.2.2" {
		t.Fatalf("order wrong: %+v", a)
	}
}
