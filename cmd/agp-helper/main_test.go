//go:build linux

package main

import (
	"path/filepath"
	"testing"
)

func TestInvalidCLIArgumentsNeverStartRuntime(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"run"}, {"initialize"}, {"stage-initial"}, {"unknown", "--config", "/tmp/missing-helper-config"}, {"run", "--unexpected"}, {"run", "--config"}, {"run", "--config", "x", "extra"}, {"initialize", "--config", "x", "extra"}, {"stage-initial", "--config", "x", "extra"}, {"run", "--config", ""}} {
		if err := run(args); err == nil {
			t.Fatalf("invalid CLI accepted: %#v", args)
		}
	}
}
func TestMissingInstallerConfigurationFailsClosed(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent-helper-config")
	for _, mode := range []string{"run", "initialize", "stage-initial"} {
		if err := run([]string{mode, "--config", absent}); err == nil {
			t.Fatalf("%s accepted missing installer configuration", mode)
		}
	}
}
