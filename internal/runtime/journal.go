package runtime

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/securityjournal"
)

// OpenJournalClient connects to an independently deployed authority. These
// credentials and its CA must not be the EdgeAuth client identity or browser PKI.
func OpenJournalClient() (*securityjournal.Client, error) {
	values := make(map[string]string)
	for _, name := range []string{"AGP_JOURNAL_URL", "AGP_JOURNAL_AUTHORITY_ID", "AGP_JOURNAL_KEY_ID", "AGP_JOURNAL_PUBLIC_KEY", "AGP_JOURNAL_CLIENT_CERT", "AGP_JOURNAL_CLIENT_KEY", "AGP_JOURNAL_CA"} {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			return nil, errors.New(name + " is required for the secure profile")
		}
		values[name] = value
	}
	public, e := securityjournal.DecodePublicKey(values["AGP_JOURNAL_PUBLIC_KEY"])
	if e != nil {
		return nil, e
	}
	clientTLS, e := securityjournal.LoadClientTLS(values["AGP_JOURNAL_CLIENT_CERT"], values["AGP_JOURNAL_CLIENT_KEY"], values["AGP_JOURNAL_CA"], "")
	if e != nil {
		return nil, e
	}
	return securityjournal.NewClient(securityjournal.ClientConfig{URL: values["AGP_JOURNAL_URL"], AuthorityID: values["AGP_JOURNAL_AUTHORITY_ID"], KeyID: values["AGP_JOURNAL_KEY_ID"], PublicKey: public, TLSConfig: clientTLS, Timeout: 3 * time.Second})
}
