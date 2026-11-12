package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func logWith(n int) string {
	var b strings.Builder
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.Local)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%s h sshd[1]: Failed password for root from 203.0.113.5 port %d ssh2\n", base.Add(time.Duration(i)*time.Second).Format("Jan _2 15:04:05"), 4000+i)
	}
	return b.String()
}

func TestCLIFileStdinJSONAndExitCodes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(p, []byte(logWith(15)), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"-year", "2026", p}, nil, &out, &errb); code != 2 || !strings.Contains(out.String(), "brute_force") {
		t.Fatalf("file run: %d %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"-year", "2026", "-json", "-"}, strings.NewReader(logWith(15)), &out, &errb); code != 2 {
		t.Fatalf("stdin run: %d", code)
	}
	var doc struct {
		Events int `json:"events"`
		Alerts []struct{ Type, IP string }
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.Events != 15 || doc.Alerts[0].IP != "203.0.113.5" {
		t.Fatalf("bad JSON: %v %s", err, out.String())
	}
	out.Reset()
	if code := run([]string{"-year", "2026", "-allow", "203.0.113.5", p}, nil, &out, &errb); code != 0 {
		t.Fatalf("allow-listed run should exit 0, got %d", code)
	}
	if run([]string{"/does/not/exist"}, nil, &out, &errb) != 2 || run([]string{"-nope"}, nil, &out, &errb) != 2 {
		t.Fatal("errors must exit 2")
	}
}
