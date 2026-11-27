package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/netwizd/agp/internal/compiler"
	"github.com/netwizd/agp/internal/version"
)

// CompilerOptions pins the actual running binary, including builds without Git
// metadata. This identifies a build; it does not assert runtime qualification.
func CompilerOptions(reservedOrigins ...string) (compiler.Options, error) {
	reserved := []string{}
	seen := map[string]bool{}
	for _, origin := range reservedOrigins {
		u, e := url.Parse(origin)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return compiler.Options{}, fmt.Errorf("invalid reserved compiler origin")
		}
		host := strings.ToLower(u.Hostname())
		if !seen[host] {
			reserved = append(reserved, host)
			seen[host] = true
		}
	}
	sort.Strings(reserved)
	path, err := os.Executable()
	if err != nil {
		return compiler.Options{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return compiler.Options{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return compiler.Options{}, err
	}
	return compiler.Options{Version: version.Version, BuildDigest: "sha256:" + hex.EncodeToString(h.Sum(nil)), MinimumWAFMode: "detection", ReservedHosts: reserved}, nil
}
