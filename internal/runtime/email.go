package runtime

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/inventory"
	"github.com/netwizd/agp/internal/mailtransport"
	"github.com/netwizd/agp/internal/secretfiles"
)

var errEmailStartup = errors.New("email_configuration_rejected")

// EmailConfig is protected installation policy. Neither the message recipient
// nor an HTTP caller can select the SMTP server, trust roots, keys or secrets.
type EmailConfig struct {
	APIVersion      string     `json:"apiVersion"`
	KeyringFile     string     `json:"keyringFile"`
	SecretsManifest string     `json:"secretsManifest"`
	AllowedCIDRs    []string   `json:"allowedCidrs"`
	SMTP            SMTPConfig `json:"smtp"`
}
type SMTPConfig struct {
	Host                    string `json:"host"`
	Port                    int    `json:"port"`
	Transport               string `json:"transport"`
	HelloName               string `json:"helloName"`
	From                    string `json:"from"`
	Authentication          string `json:"authentication"`
	Username                string `json:"username"`
	PasswordVersionID       string `json:"passwordVersionId"`
	CAVersionID             string `json:"caVersionId"`
	OperationTimeoutSeconds int    `json:"operationTimeoutSeconds"`
}
type mailFileSecrets struct{ resolver *secretfiles.Resolver }

func (r mailFileSecrets) ResolveMailSecrets(ctx context.Context, passwordID, caID string) (mailtransport.Secrets, error) {
	var out mailtransport.Secrets
	var e error
	if passwordID != "" {
		out.Password, e = r.resolver.Read(ctx, passwordID, secretfiles.SMTPPassword)
		if e != nil {
			return out, e
		}
	}
	out.CACertificatesPEM, e = r.resolver.Read(ctx, caID, secretfiles.SMTPCA)
	if e != nil {
		clear(out.Password)
		return mailtransport.Secrets{}, e
	}
	return out, nil
}

func OpenEmailService(service *identity.Service, file string) (*identity.EmailService, error) {
	if file == "" {
		return nil, nil
	}
	if service == nil || !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return nil, errEmailStartup
	}
	raw, e := inventory.ReadProtectedFile(file, true)
	if e != nil {
		return nil, errEmailStartup
	}
	defer clear(raw)
	var cfg EmailConfig
	if configmodel.StrictJSON(bytes.NewReader(raw), &cfg, 64<<10) != nil || cfg.APIVersion != "agp.email/v1alpha1" || len(cfg.AllowedCIDRs) == 0 || len(cfg.AllowedCIDRs) > 64 || cfg.SMTP.OperationTimeoutSeconds < 1 || cfg.SMTP.OperationTimeoutSeconds > 30 {
		return nil, errEmailStartup
	}
	prefixes := make([]netip.Prefix, 0, len(cfg.AllowedCIDRs))
	seen := map[netip.Prefix]bool{}
	for _, cidr := range cfg.AllowedCIDRs {
		p, e := netip.ParsePrefix(cidr)
		if e != nil || p != p.Masked() || p.Addr().Is4In6() || seen[p] {
			return nil, errEmailStartup
		}
		prefixes = append(prefixes, p)
		seen[p] = true
	}
	resolver, e := secretfiles.Open(cfg.SecretsManifest)
	if e != nil {
		return nil, errEmailStartup
	}
	smtp := cfg.SMTP
	secrets := mailFileSecrets{resolver}
	sender, e := mailtransport.New(mailtransport.Config{Host: smtp.Host, Port: smtp.Port, Transport: smtp.Transport, HelloName: smtp.HelloName, From: smtp.From, Authentication: smtp.Authentication, Username: smtp.Username, PasswordVersionID: smtp.PasswordVersionID, CAVersionID: smtp.CAVersionID, OperationTimeout: time.Duration(smtp.OperationTimeoutSeconds) * time.Second}, secrets, prefixes)
	if e != nil {
		return nil, errEmailStartup
	}
	// Validate availability and immutable hashes before recovery/listeners, without
	// connecting to SMTP or logging a password/certificate/path.
	check, e := secrets.ResolveMailSecrets(context.Background(), smtp.PasswordVersionID, smtp.CAVersionID)
	clear(check.Password)
	clear(check.CACertificatesPEM)
	if e != nil {
		return nil, errEmailStartup
	}
	keys, e := identity.LoadEmailKeyring(cfg.KeyringFile)
	if e != nil {
		return nil, errEmailStartup
	}
	email, e := identity.NewEmailService(service, keys, sender)
	if e != nil {
		return nil, errEmailStartup
	}
	service.WithEmail(email)
	return email, nil
}

// RunEmailOutbox performs bounded single submissions. Terminal failed/unknown
// jobs are never retried; only a new explicit challenge can create a new job.
func RunEmailOutbox(ctx context.Context, service *identity.EmailService) {
	if service == nil {
		return
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if service.Cleanup(ctx) != nil {
			timer.Reset(time.Second)
			continue
		}
		processed, e := service.ProcessOne(ctx)
		delay := time.Second
		if e == nil && processed {
			delay = 25 * time.Millisecond
		}
		timer.Reset(delay)
	}
}
