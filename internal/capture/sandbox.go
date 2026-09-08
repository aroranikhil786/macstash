package capture

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// SandboxEnv marks a process that is already running inside the sandbox, so the
// re-exec happens exactly once.
const SandboxEnv = "MACSTASH_SANDBOXED"

const sandboxExec = "/usr/bin/sandbox-exec"

// sandboxProfile denies every network operation. Capture has no need for the
// network — it reads local files and asks locally installed tools what they have
// installed — so denying it outright turns "macstash does not exfiltrate your
// config" from a promise into a property of the process.
//
// allow default is deliberate: capture must still read a wide slice of $HOME, and
// a deny-by-default profile large enough to permit that would be its own source
// of bugs. The one thing that matters is closed.
const sandboxProfile = `(version 1)
(allow default)
(deny network*)
`

// ReExecSandboxed replaces the current process with a copy of itself running
// under a no-network sandbox. It returns nil, having done nothing, if we are
// already sandboxed.
//
// If sandbox-exec is unavailable the capture proceeds, with a visible warning
// rather than a silent downgrade: sandbox-exec has been deprecated by Apple for
// years without being removed, and the day it disappears the user should be told
// which guarantee they just lost rather than discovering it in a changelog.
func ReExecSandboxed() error {
	if os.Getenv(SandboxEnv) != "" {
		return nil
	}
	if _, err := os.Stat(sandboxExec); err != nil {
		fmt.Fprintln(os.Stderr,
			"warning: /usr/bin/sandbox-exec is unavailable, so capture is running without\n"+
				"         the no-network sandbox. macstash still opens no sockets of its own,\n"+
				"         but that is now a property of the code rather than of the process.")
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	args := append([]string{sandboxExec, "-p", sandboxProfile, self}, os.Args[1:]...)
	env := append(os.Environ(), SandboxEnv+"=1")
	return syscall.Exec(sandboxExec, args, env)
}

// commandExists reports whether name is on PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
