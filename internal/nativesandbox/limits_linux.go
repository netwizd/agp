//go:build linux

package nativesandbox

import (
	"runtime/debug"

	"golang.org/x/sys/unix"
)

var limits = []struct {
	resource int
	maximum  uint64
}{
	{unix.RLIMIT_AS, 4 << 30}, {unix.RLIMIT_CPU, 30}, {unix.RLIMIT_NOFILE, 1024},
	{unix.RLIMIT_NPROC, 4096}, {unix.RLIMIT_FSIZE, 64 << 20}, {unix.RLIMIT_CORE, 0},
}

// ApplyLocalProcessLimits is exclusively for a dedicated, one-shot process
// before loading any inputs. A server must receive equivalent inherited limits;
// RunNginx never changes process-global settings of its caller.
func ApplyLocalProcessLimits() error {
	debug.SetMemoryLimit(512 << 20)
	for _, l := range limits {
		var v unix.Rlimit
		if unix.Getrlimit(l.resource, &v) != nil {
			return ErrUnavailable
		}
		if unix.Setrlimit(l.resource, &unix.Rlimit{Cur: min(v.Cur, l.maximum), Max: min(v.Max, l.maximum)}) != nil {
			return ErrUnavailable
		}
	}
	return nil
}

func CheckLimits() error {
	for _, l := range limits {
		var v unix.Rlimit
		if unix.Getrlimit(l.resource, &v) != nil || v.Cur > l.maximum || v.Max > l.maximum {
			return ErrUnavailable
		}
	}
	return nil
}
