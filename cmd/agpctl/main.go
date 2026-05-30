package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/runtime"
	"github.com/netwizd/agp/internal/storage"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "hash-password":
		if err := hashPassword(); err != nil {
			fmt.Fprintf(os.Stderr, "hash-password failed: %v\n", err)
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
	fmt.Fprintln(os.Stderr, "  agpctl hash-password")
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
		Name:        name,
		Description: "Bootstrap administrators group",
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
