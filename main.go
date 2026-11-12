package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jvch0512/log-sentinel/sentinel"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, out, errw io.Writer) int {
	fs := flag.NewFlagSet("log-sentinel", flag.ContinueOnError)
	fs.SetOutput(errw)
	cfg := sentinel.DefaultConfig()
	fs.DurationVar(&cfg.Window, "window", cfg.Window, "sliding detection window")
	fs.IntVar(&cfg.BruteThreshold, "brute", cfg.BruteThreshold, "failures inside the window that count as brute force")
	fs.IntVar(&cfg.SprayThreshold, "spray", cfg.SprayThreshold, "distinct usernames inside the window that count as spraying")
	year := fs.Int("year", time.Now().Year(), "year for syslog timestamps that carry none")
	allow := fs.String("allow", "", "comma-separated trusted source IPs to ignore")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	for _, a := range strings.Split(*allow, ",") {
		if a = strings.TrimSpace(a); a != "" {
			cfg.Allow[a] = true
		}
	}
	var in io.Reader = stdin
	if fs.NArg() > 0 && fs.Arg(0) != "-" {
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			fmt.Fprintln(errw, "error:", err)
			return 2
		}
		defer f.Close()
		in = f
	}
	events, err := sentinel.Parse(in, *year, time.Local)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 2
	}
	alerts := sentinel.Detect(events, cfg)
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"events": len(events), "alerts": alerts})
	} else {
		for _, a := range alerts {
			fmt.Fprintf(out, "[%-8s] %-22s %-39s %3d events  %s -> %s\n    %s\n", strings.ToUpper(a.Severity), a.Type, a.IP, a.Count,
				a.First.Format("Jan 2 15:04:05"), a.Last.Format("15:04:05"), a.Detail)
			if len(a.Users) > 0 {
				u := a.Users
				if len(u) > 8 {
					u = append(u[:8:8], "...")
				}
				fmt.Fprintf(out, "    users: %s\n", strings.Join(u, ", "))
			}
		}
		fmt.Fprintf(out, "%d event(s) parsed, %d alert(s)\n", len(events), len(alerts))
	}
	if len(alerts) > 0 {
		return 2
	}
	return 0
}
