package restore

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/classify"
)

// RestoreLaunchAgents writes background jobs, but only when explicitly asked.
//
// The default is to list them and write nothing. A LaunchAgent is a standing
// instruction to run a program at every login; reinstating one silently is the
// single most consequential thing a restore could do without being asked, and
// many of them were installed by applications rather than chosen by the person
// running this. The full command line is printed for each, because "com.acme.
// updater" tells you nothing and the actual argv tells you everything.
// validAgentFile reports whether a manifest-supplied LaunchAgent file name is a
// plain basename that stays inside the LaunchAgents directory.
func validAgentFile(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsRune(name, filepath.Separator) || strings.ContainsRune(name, '/') {
		return false
	}
	if strings.ContainsRune(name, 0) {
		return false
	}
	if filepath.Clean(name) != name {
		return false
	}
	if !strings.HasSuffix(name, ".plist") {
		return false
	}
	return true
}

func RestoreLaunchAgents(home string, agents []bundle.LaunchAgent, staging string, include, apply bool, out io.Writer) error {
	if len(agents) == 0 {
		return nil
	}

	fmt.Fprintf(out, "\nLaunchAgents — %d background job(s) found on the old machine.\n", len(agents))
	fmt.Fprintln(out, "These run at every login. Read what each one actually executes:")
	for _, a := range agents {
		cmd := strings.Join(a.ProgramArguments, " ")
		if cmd == "" {
			cmd = "(no ProgramArguments — inspect the plist)"
		}
		var when []string
		if a.RunAtLoad {
			when = append(when, "at login")
		}
		if a.KeepAlive {
			when = append(when, "kept alive")
		}
		suffix := ""
		if len(when) > 0 {
			suffix = "  [" + strings.Join(when, ", ") + "]"
		}
		fmt.Fprintf(out, "\n  %s%s\n      %s\n", a.Label, suffix, cmd)
	}

	if !include {
		fmt.Fprintln(out, "\nNot restored. Pass --include-launch-agents if you want these back, having")
		fmt.Fprintln(out, "read the commands above. Anything installed by an application will come")
		fmt.Fprintln(out, "back on its own when you reinstall that application.")
		return nil
	}
	if !apply {
		fmt.Fprintln(out, "\n--include-launch-agents was passed: these would be written on --apply.")
		return nil
	}

	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	written := 0
	for _, a := range agents {
		// The file name comes out of the manifest, which is attacker-controlled
		// for any bundle the user did not create. filepath.Join cleans ".."
		// segments rather than rejecting them, so an unvalidated name escapes
		// both the staging tree and ~/Library/LaunchAgents — reaching, among
		// other things, VS Code's settings.json, which is a code-execution
		// surface. A genuine name always comes from os.ReadDir and is a bare
		// basename, so this rejects nothing legitimate.
		if !validAgentFile(a.File) {
			fmt.Fprintf(out, "  REFUSED %s — not a plain file name\n", a.File)
			continue
		}
		if never, reason := classify.IsNever("Library/LaunchAgents/" + a.File); never {
			fmt.Fprintf(out, "  REFUSED %s — %s\n", a.File, reason)
			continue
		}
		data, err := os.ReadFile(filepath.Join(staging, "launchagents", a.File))
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, a.File), data, 0o644); err != nil {
			return err
		}
		written++
	}
	fmt.Fprintf(out, "\nWrote %d LaunchAgent(s). They take effect at your next login, or run\n"+
		"`launchctl load ~/Library/LaunchAgents/<file>` to start one now.\n", written)
	return nil
}
