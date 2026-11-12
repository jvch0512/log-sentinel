package sentinel

import (
	"sort"
	"time"
)

// Alert is a detection result for one source address.
type Alert struct {
	Severity string    `json:"severity"`
	Type     string    `json:"type"`
	IP       string    `json:"ip"`
	Count    int       `json:"count"`
	Users    []string  `json:"users,omitempty"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Detail   string    `json:"detail"`
}

// Config holds detection thresholds.
type Config struct {
	Window         time.Duration // sliding window for bursts
	BruteThreshold int           // failures from one IP inside Window
	SprayThreshold int           // distinct usernames from one IP inside Window
	Allow          map[string]bool
}

// DefaultConfig is a sane starting point for an internet-facing SSH daemon.
func DefaultConfig() Config {
	return Config{Window: 10 * time.Minute, BruteThreshold: 10, SprayThreshold: 5, Allow: map[string]bool{}}
}

func uniq(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Detect finds brute force, password spraying and, most importantly, successful logins that follow a burst of failures.
func Detect(events []Event, c Config) []Alert {
	if c.Window <= 0 {
		c = DefaultConfig()
	}
	byIP := map[string][]Event{}
	for _, e := range events {
		if c.Allow[e.IP] {
			continue
		}
		byIP[e.IP] = append(byIP[e.IP], e)
	}
	var alerts []Alert
	for addr, evs := range byIP {
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
		var burst, spray, compromise *Alert
		lo := 0
		for hi, e := range evs {
			for evs[hi].Time.Sub(evs[lo].Time) > c.Window {
				lo++
			}
			fails, users := 0, map[string]int{}
			for _, w := range evs[lo : hi+1] {
				if w.Kind == Failed || w.Kind == Invalid {
					fails++
					users[w.User]++
				}
			}
			if e.Kind == Accepted && fails >= c.BruteThreshold/2 && fails > 0 && compromise == nil {
				compromise = &Alert{Severity: "critical", Type: "success_after_failures", IP: addr, Count: fails, Users: []string{e.User},
					First: evs[lo].Time, Last: e.Time,
					Detail: "successful " + e.Method + " login for '" + e.User + "' right after failed attempts from the same address: treat as possible credential compromise"}
			}
			if (e.Kind == Failed || e.Kind == Invalid) && fails >= c.BruteThreshold {
				if burst == nil {
					burst = &Alert{Severity: "high", Type: "brute_force", IP: addr, First: evs[lo].Time}
				}
				burst.Count, burst.Last, burst.Users = fails, e.Time, uniq(users)
				burst.Detail = "repeated failed logins from one address inside the detection window"
			}
			if (e.Kind == Failed || e.Kind == Invalid) && len(users) >= c.SprayThreshold {
				if spray == nil {
					spray = &Alert{Severity: "high", Type: "password_spraying", IP: addr, First: evs[lo].Time}
				}
				spray.Count, spray.Last, spray.Users = fails, e.Time, uniq(users)
				spray.Detail = "many different usernames tried from one address"
			}
		}
		for _, a := range []*Alert{compromise, burst, spray} {
			if a != nil {
				alerts = append(alerts, *a)
			}
		}
	}
	order := map[string]int{"critical": 0, "high": 1, "medium": 2}
	sort.Slice(alerts, func(i, j int) bool {
		if order[alerts[i].Severity] != order[alerts[j].Severity] {
			return order[alerts[i].Severity] < order[alerts[j].Severity]
		}
		if alerts[i].Count != alerts[j].Count {
			return alerts[i].Count > alerts[j].Count
		}
		return alerts[i].IP < alerts[j].IP
	})
	return alerts
}
