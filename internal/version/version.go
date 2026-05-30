package version

import "runtime"

var (
	Version = "v1.0.0-dev"
	Commit  = "unknown"
	BuiltAt = "unknown"
)

func Info() map[string]string {
	return map[string]string{
		"version":    Version,
		"commit":     Commit,
		"built_at":   BuiltAt,
		"go_version": runtime.Version(),
	}
}
