package securityjournal

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func ReadSigningKey(file string) (ed25519.PrivateKey, error) {
	info, e := os.Stat(file)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
		return nil, errors.New("signing key must be a private regular file (0600)")
	}
	b, e := os.ReadFile(file)
	if e != nil {
		return nil, e
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, bad("PKCS8 signing key PEM")
	}
	v, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, bad("PKCS8 signing key")
	}
	key, ok := v.(ed25519.PrivateKey)
	if !ok {
		return nil, bad("signing key must be Ed25519")
	}
	return key, nil
}
func LoadClientTLS(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	cert, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		return nil, errors.New("load journal client certificate")
	}
	ca, e := readCA(caFile)
	if e != nil {
		return nil, e
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: ca, ServerName: serverName}, nil
}
func LoadServerTLS(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		return nil, errors.New("load journal server certificate")
	}
	ca, e := readCA(clientCAFile)
	if e != nil {
		return nil, e
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: ca, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}
func readCA(file string) (*x509.CertPool, error) {
	b, e := os.ReadFile(file)
	if e != nil {
		return nil, errors.New("read journal CA")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, bad("journal CA PEM")
	}
	return pool, nil
}
