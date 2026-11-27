package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/runtime"
	"github.com/netwizd/agp/internal/storage"
	"github.com/netwizd/agp/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "waf-render":
		if err := wafRender(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "waf-render failed: %v\n", err)
			os.Exit(1)
		}
	case "waf-repository":
		if err := wafRepository(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "waf-repository failed: %v\n", err)
			os.Exit(1)
		}
	case "configuration-access":
		if err := configurationAccess(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "configuration-access failed: %v\n", err)
			os.Exit(1)
		}
	case "configuration-profile":
		if err := configurationProfile(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "configuration-profile failed: %v\n", err)
			os.Exit(1)
		}
	case "version":
		info := version.Info()
		fmt.Printf("agpctl %s commit=%s built_at=%s go=%s\n", info["version"], info["commit"], info["built_at"], info["go_version"])
	case "hash-password":
		if err := hashPassword(); err != nil {
			fmt.Fprintf(os.Stderr, "hash-password failed: %v\n", err)
			os.Exit(1)
		}
	case "identity-profile":
		if err := identityProfile(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "identity-profile failed: %v\n", err)
			os.Exit(1)
		}
	case "nginx-edge":
		if err := edgeNginx(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "nginx-edge failed: %v\n", err)
			os.Exit(1)
		}
	case "gateway-register":
		if err := gatewayRegister(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "gateway-register failed: %v\n", err)
			os.Exit(1)
		}
	case "security-state":
		if err := securityState(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "security-state failed: %v\n", err)
			os.Exit(1)
		}
	case "session-profile":
		if err := sessionProfile(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "session-profile failed: %v\n", err)
			os.Exit(1)
		}
	case "create-admin":
		if err := createAdmin(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "create-admin failed: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  agpctl version")
	fmt.Fprintln(os.Stderr, "  agpctl waf-render --policy PATH --bundle DIR --work DIR --mode detection|blocking|off (render only)")
	fmt.Fprintln(os.Stderr, "  agpctl waf-repository --trust-config PATH --store DIR --import-bundle DIR (offline trust administrator)")
	fmt.Fprintln(os.Stderr, "  agpctl configuration-access --bootstrap-manifest PATH (initial installation only; CP stopped)")
	fmt.Fprintln(os.Stderr, "  agpctl configuration-profile [--preview | --activate] (activation: CP stopped)")
	fmt.Fprintln(os.Stderr, "  agpctl nginx-edge --origin HTTPS_ORIGIN --socket PATH --certificate PATH --key PATH (generate only)")
	fmt.Fprintln(os.Stderr, "  agpctl identity-profile [--preview | --activate --revoke-sessions]")
	fmt.Fprintln(os.Stderr, "  agpctl gateway-register --id ID --node ID --origin HTTPS_ORIGIN --callback URI --resource ID --generation ID (CP stopped)")
	fmt.Fprintln(os.Stderr, "  agpctl security-state {head|prepare-restore|append-approved|replay|ready}")
	fmt.Fprintln(os.Stderr, "  agpctl hash-password")
	fmt.Fprintln(os.Stderr, "  agpctl session-profile [--preview | --apply --revoke-sessions]")
	fmt.Fprintln(os.Stderr, "  agpctl create-admin -username admin [-display-name Administrator] [-group-name Administrators]")
}

func hashPassword() error {
	password, err := readPasswordFromStdin()
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(password, auth.DefaultArgon2idParams)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	fmt.Println(hash)
	return nil
}

func createAdmin(args []string) error {
	flags := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	username := flags.String("username", "admin", "admin username")
	displayName := flags.String("display-name", "Administrator", "admin display name")
	groupName := flags.String("group-name", "Administrators", "admin group name")
	if err := flags.Parse(args); err != nil {
		return err
	}

	password, err := readPasswordFromStdin()
	if err != nil {
		return err
	}
	passwordHash, err := auth.HashPassword(password, auth.DefaultArgon2idParams)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx := context.Background()
	store, err := runtime.OpenStore(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate store: %w", err)
	}

	if lease, ok := store.(interface {
		AcquireIdentityLease(context.Context) (func(), error)
	}); ok {
		release, e := lease.AcquireIdentityLease(ctx)
		if e != nil {
			return e
		}
		defer release()
	}
	if err := store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
		rows, e := tx.Query(ctx, `SELECT authority_id FROM security_state WHERE id=1`)
		if e != nil {
			return e
		}
		defer rows.Close()
		if rows.Next() {
			return errors.New("bootstrap create-admin is forbidden after secure activation; use an authenticated management command")
		}
		return rows.Err()
	}); err != nil {
		return err
	}
	groupID, err := ensureGroup(ctx, store, *groupName)
	if err != nil {
		return err
	}

	user, err := store.CreateUser(ctx, domain.UserInput{
		Username:     normalizeUsername(*username),
		PasswordHash: passwordHash,
		DisplayName:  strings.TrimSpace(*displayName),
		IsAdmin:      true,
		GroupIDs:     []string{groupID},
	})
	if err != nil {
		if errors.Is(err, storage.ErrConflict) {
			return fmt.Errorf("admin user %q already exists", normalizeUsername(*username))
		}
		return fmt.Errorf("create admin user: %w", err)
	}
	fmt.Printf("created admin user %s (%s)\n", user.Username, user.ID)
	return nil
}

func ensureGroup(ctx context.Context, store storage.Store, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("group name is required")
	}
	groups, err := store.ListGroups(ctx)
	if err != nil {
		return "", fmt.Errorf("list groups: %w", err)
	}
	for _, group := range groups {
		if strings.EqualFold(group.Name, name) {
			return group.ID, nil
		}
	}
	group, err := store.CreateGroup(ctx, domain.GroupInput{
		Name:          name,
		Description:   "Bootstrap administrators group",
		PermissionIDs: authz.AllPermissions(),
	})
	if err != nil {
		return "", fmt.Errorf("create administrators group: %w", err)
	}
	return group.ID, nil
}

func readPasswordFromStdin() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	password = strings.TrimRight(password, "\r\n")
	if password == "" {
		return "", errors.New("password is required on stdin")
	}
	return password, nil
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func sessionProfile(args []string) error {
	flags := flag.NewFlagSet("session-profile", flag.ContinueOnError)
	preview := flags.Bool("preview", false, "preview the configured session profile without changes")
	apply := flags.Bool("apply", false, "apply the configured profile")
	revoke := flags.Bool("revoke-sessions", false, "explicitly revoke all sessions when changing profile")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*apply && *preview) || (*revoke && !*apply) {
		return errors.New("use --preview or --apply --revoke-sessions")
	}
	if *apply && !*revoke {
		return errors.New("profile changes require --revoke-sessions")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	store, err := runtime.OpenStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	profile := cfg.SessionProfile()
	if *apply {
		if cfg.SecureProfile {
			return errors.New("use identity-profile --activate --revoke-sessions for secure activation")
		}
		if err := store.Migrate(ctx); err != nil {
			return err
		}
		revoked, err := store.ApplySessionProfile(ctx, profile)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"profile": profile, "fingerprint": profile.Fingerprint(), "revoked_sessions": revoked, "applied": true})
	}
	current, err := store.GetSessionProfile(ctx)
	if err != nil {
		return fmt.Errorf("read profile (schema migration must already be applied for preview): %w", err)
	}
	resources, err := store.ListResources(ctx)
	if err != nil {
		return err
	}
	for _, resource := range resources {
		if err := cfg.ValidateResourceHost(resource.PublicHost); err != nil {
			return fmt.Errorf("resource %s: %w", resource.ID, err)
		}
	}
	matches := storage.MatchSessionProfile(current, profile) == nil
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"current_profile": current, "requested_profile": profile, "fingerprint": profile.Fingerprint(), "reset_required": !matches, "applied": false})
}
