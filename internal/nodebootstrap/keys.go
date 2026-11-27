// Package nodebootstrap implements the node side of the operator-approved
// enrollment protocol. Private keys are generated locally and never leave it.
package nodebootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/netwizd/agp/internal/inventory"
	"golang.org/x/sys/unix"
)

var (
	ErrInvalid       = errors.New("invalid agent identity input")
	ErrProtectedPath = errors.New("agent identity requires a private installation-owned directory without symbolic links")
	ErrResponse      = errors.New("agent identity response rejected")
	ErrTransport     = errors.New("agent identity transport unavailable")
)

func fingerprint(b []byte) string { v := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(v[:]) }

// privateDirectory pins all traversed directory descriptors before writing.
// A root-owned sticky /tmp is allowed only before an immediate private child.
func privateDirectory(name string) (*os.File, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || name == "/" {
		return nil, ErrProtectedPath
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, ErrProtectedPath
	}
	dir := "/"
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	privateChild := false
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			next, e := unix.Openat(fd, parts[i], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
			_ = unix.Close(fd)
			if e != nil {
				return nil, ErrProtectedPath
			}
			fd = next
			dir = filepath.Join(dir, parts[i])
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
			_ = unix.Close(fd)
			return nil, ErrProtectedPath
		}
		if (privateChild || i == len(parts)-1) && (st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0) {
			_ = unix.Close(fd)
			return nil, ErrProtectedPath
		}
		privateChild = false
		if st.Mode&0022 != 0 {
			if dir != "/tmp" || st.Uid != 0 || st.Mode&unix.S_ISVTX == 0 || i == len(parts)-1 {
				_ = unix.Close(fd)
				return nil, ErrProtectedPath
			}
			privateChild = true
		}
	}
	return os.NewFile(uintptr(fd), name), nil
}

func createAt(dir *os.File, name string, data []byte) error {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrProtectedPath
	}
	f := os.NewFile(uintptr(fd), name)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = dir.Sync()
	}
	return err
}

// Generate creates a fresh key and CSR once. It never overwrites a previous key.
func Generate(directory string) (string, error) {
	dir, err := privateDirectory(directory)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	defer clear(key)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	defer clear(der)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return "", err
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(keyPEM)
	if err = createAt(dir, "key.pem", keyPEM); err != nil {
		return "", err
	}
	if err = createAt(dir, "request.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})); err != nil {
		return "", err
	}
	return fingerprint(spki), nil
}

func readRequest(directory string) ([]byte, ed25519.PrivateKey, error) {
	dir, err := privateDirectory(directory)
	if err != nil {
		return nil, nil, err
	}
	defer dir.Close()
	// Read using the same pinned directory, not a second path traversal.
	read := func(name string) ([]byte, error) {
		fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, ErrProtectedPath
		}
		f := os.NewFile(uintptr(fd), name)
		defer f.Close()
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || st.Nlink != 1 || st.Size > 16384 {
			return nil, ErrProtectedPath
		}
		return readBounded(f, 16384)
	}
	keyPEM, err := read("key.pem")
	if err != nil {
		return nil, nil, err
	}
	defer clear(keyPEM)
	block, rest := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, ErrInvalid
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, nil, ErrInvalid
	}
	csrPEM, err := read("request.pem")
	if err != nil {
		clear(key)
		return nil, nil, err
	}
	csrBlock, extra := pem.Decode(csrPEM)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" || len(csrBlock.Headers) != 0 || len(bytes.TrimSpace(extra)) != 0 {
		clear(key)
		return nil, nil, ErrInvalid
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil || csr.CheckSignature() != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, mustSPKI(key.Public())) || len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.URIs)+len(csr.EmailAddresses) != 0 {
		clear(key)
		return nil, nil, ErrInvalid
	}
	return csrPEM, key, nil
}

func mustSPKI(key any) []byte { b, _ := x509.MarshalPKIXPublicKey(key); return b }

func loadCA(name, pin string) (*x509.Certificate, error) {
	b, err := inventory.ReadProtectedFile(name, false)
	if err != nil {
		return nil, ErrProtectedPath
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalid
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !c.IsCA || c.KeyUsage&x509.KeyUsageCertSign == 0 || fingerprint(c.Raw) != pin {
		return nil, ErrInvalid
	}
	return c, nil
}

// RemoveTokenFile consumes only the same private regular file that supplied the
// successful enrollment. It does not follow or delete a substituted pathname.
func RemoveTokenFile(name, token string) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return ErrProtectedPath
	}
	dir, err := privateDirectory(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer dir.Close()
	base := filepath.Base(name)
	fd, err := unix.Openat(int(dir.Fd()), base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrProtectedPath
	}
	f := os.NewFile(uintptr(fd), base)
	defer f.Close()
	var st, current unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || st.Nlink != 1 {
		return ErrProtectedPath
	}
	actual, err := ReadToken(f)
	if err != nil || actual != token {
		return ErrProtectedPath
	}
	if unix.Fstatat(int(dir.Fd()), base, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || current.Dev != st.Dev || current.Ino != st.Ino || current.Nlink != 1 {
		return ErrProtectedPath
	}
	if unix.Unlinkat(int(dir.Fd()), base, 0) != nil {
		return ErrProtectedPath
	}
	return dir.Sync()
}
