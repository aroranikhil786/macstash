package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// ScanLaunchAgents reads ~/Library/LaunchAgents.
//
// A LaunchAgent is a standing instruction to run a program at every login. That
// makes it the highest-consequence thing in a bundle by some distance: restoring
// one silently arranges for code to execute on the new machine forever, and the
// person restoring may have forgotten it exists — half of these are installed by
// applications, not by their owner.
//
// So they are captured, never restored by default, and their ProgramArguments
// are printed before anything is written. Seeing the actual command is the only
// way to make an informed decision about it.
func ScanLaunchAgents(home string) []bundle.LaunchAgent {
	dir := filepath.Join(home, "Library", "LaunchAgents")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var agents []bundle.LaunchAgent
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		a := bundle.LaunchAgent{File: e.Name()}

		out, ok := run("plutil", "-convert", "json", "-o", "-", path)
		if ok {
			var parsed struct {
				Label            string   `json:"Label"`
				ProgramArguments []string `json:"ProgramArguments"`
				Program          string   `json:"Program"`
				RunAtLoad        bool     `json:"RunAtLoad"`
				KeepAlive        any      `json:"KeepAlive"`
			}
			if err := json.Unmarshal([]byte(out), &parsed); err == nil {
				a.Label = parsed.Label
				a.ProgramArguments = parsed.ProgramArguments
				if len(a.ProgramArguments) == 0 && parsed.Program != "" {
					a.ProgramArguments = []string{parsed.Program}
				}
				a.RunAtLoad = parsed.RunAtLoad
				a.KeepAlive = parsed.KeepAlive != nil
			}
		}
		if a.Label == "" {
			a.Label = strings.TrimSuffix(e.Name(), ".plist")
		}
		if data, err := os.ReadFile(path); err == nil && int64(len(data)) < bundle.MaxFileBytes {
			a.Content = data
		}
		agents = append(agents, a)
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].Label < agents[j].Label })
	return agents
}
