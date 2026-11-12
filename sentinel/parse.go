// Package sentinel turns SSH authentication logs into attack findings.
package sentinel

import (
	"bufio"
	"io"
	"regexp"
	"time"
)

// Kind classifies a log event.
type Kind string

const (
	Failed   Kind = "failed"
	Invalid  Kind = "invalid_user"
	Accepted Kind = "accepted"
)

// Event is one parsed authentication event.
type Event struct {
	Time   time.Time
	Kind   Kind
	User   string
	IP     string
	Method string
}

const ip = `([0-9a-fA-F:.]+)`

var (
	reFailed   = regexp.MustCompile(`Failed (\S+) for (?:invalid user )?(\S+) from ` + ip + ` port \d+`)
	reInvalid  = regexp.MustCompile(`Invalid user (\S*) from ` + ip)
	reAccepted = regexp.MustCompile(`Accepted (\S+) for (\S+) from ` + ip + ` port \d+`)
	reSyslog   = regexp.MustCompile(`^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})`)
	reISO      = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))`)
)

// parseTime understands classic syslog stamps (year supplied by the caller) and RFC 3339 stamps.
func parseTime(line string, year int, loc *time.Location) (time.Time, bool) {
	if m := reISO.FindStringSubmatch(line); m != nil {
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if t, err := time.Parse(layout, m[1]); err == nil {
				return t, true
			}
		}
	}
	if m := reSyslog.FindStringSubmatch(line); m != nil {
		t, err := time.ParseInLocation("2006 Jan 2 15:04:05", itoa(year)+" "+m[1]+" "+m[2]+" "+m[3], loc)
		if err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// Parse reads sshd events from r. Lines that are not SSH authentication events are ignored.
// Syslog stamps carry no year, so year is applied to them; a clearly backwards jump of months is treated as a year rollover.
func Parse(r io.Reader, year int, loc *time.Location) ([]Event, error) {
	if loc == nil {
		loc = time.UTC
	}
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var last time.Time
	for sc.Scan() {
		line := sc.Text()
		t, ok := parseTime(line, year, loc)
		if !ok {
			continue
		}
		if !last.IsZero() && t.Before(last.AddDate(0, -6, 0)) && reSyslog.MatchString(line) && !reISO.MatchString(line) {
			year++
			t, _ = parseTime(line, year, loc)
		}
		last = t
		switch {
		case reAccepted.MatchString(line):
			m := reAccepted.FindStringSubmatch(line)
			out = append(out, Event{t, Accepted, m[2], m[3], m[1]})
		case reFailed.MatchString(line):
			m := reFailed.FindStringSubmatch(line)
			out = append(out, Event{t, Failed, m[2], m[3], m[1]})
		case reInvalid.MatchString(line):
			m := reInvalid.FindStringSubmatch(line)
			out = append(out, Event{t, Invalid, m[1], m[2], ""})
		}
	}
	return out, sc.Err()
}
