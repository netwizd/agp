package inventory

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/netwizd/agp/internal/securityjournal"
	"golang.org/x/sys/unix"
)

type registryEntry struct {
	Registration
	leaf   *x509.Certificate
	digest string
}
type registry struct {
	authority string
	entries   []registryEntry
}

// openPublicFile follows no symbolic links and checks the opened file descriptors
// at every step. An otherwise protected file can be replaced through a writable
// ancestor. The only shared-directory exception is root-owned sticky /tmp,
// immediately followed by a private directory owned by this process's user.
func openPublicFile(name string) (*os.File, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, ErrUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	privateChild, e := checkPublicDirectory(fd, "/")
	if e != nil {
		_ = unix.Close(fd)
		return nil, e
	}
	directory := "/"
	for i, p := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		isDirectory := i < len(parts)-1
		if isDirectory {
			flags |= unix.O_DIRECTORY
		} else {
			// A FIFO in an invalid configuration must not block before fstat.
			flags |= unix.O_NONBLOCK
			if privateChild {
				_ = unix.Close(fd)
				return nil, ErrUnavailable
			}
		}
		next, err := unix.Openat(fd, p, flags, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, ErrUnavailable
		}
		fd = next
		if isDirectory {
			directory = filepath.Join(directory, p)
			if privateChild {
				var st unix.Stat_t
				if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
					_ = unix.Close(fd)
					return nil, ErrUnavailable
				}
			}
			privateChild, e = checkPublicDirectory(fd, directory)
			if e != nil {
				_ = unix.Close(fd)
				return nil, e
			}
		}
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || !publicFileOwner(st.Uid) || st.Mode&0022 != 0 {
		_ = unix.Close(fd)
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), name), nil
}
func publicFileOwner(uid uint32) bool { return uid == 0 || uid == uint32(os.Geteuid()) }
func checkPublicDirectory(fd int, name string) (bool, error) {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || !publicFileOwner(st.Uid) {
		return false, ErrUnavailable
	}
	if st.Mode&0022 == 0 {
		return false, nil
	}
	if name == "/tmp" && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0 {
		return true, nil
	}
	return false, ErrUnavailable
}
func loadRegistry(name string) (*registry, error) {
	f, e := openPublicFile(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var in Registry
	if decodeBounded(f, &in, 16<<20) != nil || in.APIVersion != "agp.agent-registry/v1alpha1" || !idPattern.MatchString(in.AuthorityID) || len(in.Nodes) == 0 || len(in.Nodes) > 10000 {
		return nil, ErrUnavailable
	}
	return validateRegistry(in, false)
}
func validateRegistry(in Registry, managed bool) (*registry, error) {
	if in.APIVersion != "agp.agent-registry/v1alpha1" || !idPattern.MatchString(in.AuthorityID) || len(in.Nodes) > 20000 || (!managed && len(in.Nodes) == 0) {
		return nil, ErrUnavailable
	}
	out := &registry{authority: in.AuthorityID}
	ids, certs, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}
	primaries := map[string]bool{}
	bindings := map[string]string{}
	for _, n := range in.Nodes {
		meta, _ := Digest(struct {
			Site, Name string
			Labels     map[string]string
			Groups     []string
		}{n.SiteID, n.Name, n.Labels, n.GroupIDs})
		if previous, ok := bindings[n.NodeID]; ok && previous != meta {
			return nil, ErrUnavailable
		}
		bindings[n.NodeID] = meta
		if n.AcceptUntil == nil {
			if primaries[n.NodeID] {
				return nil, ErrUnavailable
			}
			primaries[n.NodeID] = true
		} else if !managed {
			return nil, ErrUnavailable
		}
		if !idPattern.MatchString(n.NodeID) || !idPattern.MatchString(n.SiteID) || !boundedText(n.Name, 128) || n.Labels == nil || len(n.Labels) > 32 || n.GroupIDs == nil || len(n.GroupIDs) > 100 || (!managed && ids[n.NodeID]) || !digestPattern.MatchString(n.CertificateDigest) || !digestPattern.MatchString(n.PublicKeyDigest) || !digestPattern.MatchString(n.IssuerDigest) || n.IssuanceEpoch == 0 || n.IssuanceEpoch > securityjournal.MaxUInt63 || certs[n.CertificateDigest] || keys[n.PublicKeyDigest] || len(n.CertificatePEM) > 32768 {
			return nil, ErrUnavailable
		}
		for k, v := range n.Labels {
			if !labelPattern.MatchString(k) || len(v) > 128 || !utf8.ValidString(v) || strings.ContainsAny(v, "\x00\r\n") {
				return nil, ErrUnavailable
			}
		}
		groups := append([]string{}, n.GroupIDs...)
		sort.Strings(groups)
		for i, g := range groups {
			if !idPattern.MatchString(g) || i > 0 && groups[i-1] == g {
				return nil, ErrUnavailable
			}
		}
		n.GroupIDs = groups
		block, rest := pem.Decode([]byte(n.CertificatePEM))
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrUnavailable
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil || hash(leaf.Raw) != n.CertificateDigest || hash(leaf.RawSubjectPublicKeyInfo) != n.PublicKeyDigest || leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.Text(16) != n.Serial || !agentLeaf(leaf, n.NodeID) {
			return nil, ErrUnavailable
		}
		d, err := Digest(n)
		if err != nil {
			return nil, ErrUnavailable
		}
		out.entries = append(out.entries, registryEntry{Registration: n, leaf: leaf, digest: d})
		ids[n.NodeID] = true
		certs[n.CertificateDigest] = true
		keys[n.PublicKeyDigest] = true
	}
	for node := range ids {
		if !primaries[node] {
			return nil, ErrUnavailable
		}
	}
	sort.Slice(out.entries, func(i, j int) bool { return out.entries[i].NodeID < out.entries[j].NodeID })
	return out, nil
}
func agentLeaf(leaf *x509.Certificate, node string) bool {
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://agp/agent/"+node || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 {
		return false
	}
	return true
}
func (r *registry) peer(state *tls.ConnectionState, h securityjournal.Head) (*registryEntry, error) {
	if r.authority != h.AuthorityID || state == nil || state.Version != tls.VersionTLS13 || !state.HandshakeComplete || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || h.RecordedAt.IsZero() {
		return nil, ErrIdentity
	}
	leaf := state.PeerCertificates[0]
	for i := range r.entries {
		n := &r.entries[i]
		if !bytes.Equal(leaf.Raw, n.leaf.Raw) {
			continue
		}
		if n.Revoked || n.IssuanceEpoch != h.Epoch || !validAt(leaf, h.RecordedAt) || n.AcceptUntil != nil && !h.RecordedAt.Before(*n.AcceptUntil) {
			return nil, ErrIdentity
		}
		for _, chain := range state.VerifiedChains {
			if len(chain) < 2 || !bytes.Equal(chain[0].Raw, leaf.Raw) || hash(chain[1].Raw) != n.IssuerDigest {
				continue
			}
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(chain[len(chain)-1])
			for _, cert := range chain[1 : len(chain)-1] {
				intermediates.AddCert(cert)
			}
			// A receipt may be consumed for the next Freshness interval. Keep
			// that interval inside every certificate's validity, including CAs.
			lifetimeOK := true
			for _, cert := range chain {
				if !validAt(cert, h.RecordedAt) || !h.RecordedAt.Add(Freshness).Before(cert.NotAfter) {
					lifetimeOK = false
					break
				}
			}
			if _, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: h.RecordedAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e == nil && lifetimeOK {
				return n, nil
			}
		}
		return nil, ErrIdentity
	}
	return nil, ErrIdentity
}
func validAt(c *x509.Certificate, t time.Time) bool {
	return !t.Before(c.NotBefore) && t.Before(c.NotAfter)
}
