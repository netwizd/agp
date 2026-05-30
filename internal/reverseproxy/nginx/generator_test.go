package nginx

import (
	"strings"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/domain"
)

func TestGenerateResourceServer(t *testing.T) {
	resource := domain.ResourceDetail{
		Resource: domain.Resource{
			ID:          "res_e1c",
			Name:        "1C",
			InternalURL: "http://e1c.osrp.local",
			PublicHost:  "e1c.company.ru",
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		GroupIDs:   []string{"grp_admins"},
		AllowCIDRs: []string{"10.50.0.0/16"},
	}

	recommendation, err := GenerateResourceServer(resource, "portal.company.ru")
	if err != nil {
		t.Fatalf("GenerateResourceServer returned error: %v", err)
	}
	if recommendation.PublicHost != "e1c.company.ru" {
		t.Fatalf("unexpected public host: %s", recommendation.PublicHost)
	}
	if !strings.Contains(recommendation.Snippet, "server_name e1c.company.ru;") {
		t.Fatalf("snippet does not contain server_name: %s", recommendation.Snippet)
	}
	if !strings.Contains(recommendation.Snippet, "proxy_pass http://e1c.osrp.local;") {
		t.Fatalf("snippet does not contain proxy_pass: %s", recommendation.Snippet)
	}
	if len(recommendation.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %#v", recommendation.Warnings)
	}
}

func TestGenerateResourceServerRejectsUnsafeHost(t *testing.T) {
	resource := domain.ResourceDetail{
		Resource: domain.Resource{
			ID:          "res_bad",
			InternalURL: "http://internal.local",
			PublicHost:  "safe.local; include /etc/passwd;",
		},
	}

	if _, err := GenerateResourceServer(resource, "portal.company.ru"); err == nil {
		t.Fatal("expected unsafe host to be rejected")
	}
}

func TestGenerateResourceServerRejectsInvalidCIDR(t *testing.T) {
	resource := domain.ResourceDetail{
		Resource: domain.Resource{
			ID:          "res_bad",
			InternalURL: "http://internal.local",
			PublicHost:  "safe.local",
		},
		AllowCIDRs: []string{"10.50.0.0/99"},
	}

	if _, err := GenerateResourceServer(resource, "portal.company.ru"); err == nil {
		t.Fatal("expected invalid CIDR to be rejected")
	}
}
