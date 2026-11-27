package runtime

import (
	"context"
	"errors"
	"os"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/identity"
	"github.com/netwizd/agp/internal/nodeidentity"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

type IdentityRuntime struct {
	Store           storage.Store
	ReleaseLease    func()
	Service         *identity.Service
	Directory       *identity.DirectoryService
	ADConnector     *identity.ADConnector
	Email           *identity.EmailService
	OIDC            *identity.OIDCService
	Coordinator     *securitystate.Coordinator
	Journal         *securityjournal.Client
	emailCancel     context.CancelFunc
	emailDone       chan struct{}
	oidcCancel      context.CancelFunc
	oidcDone        chan struct{}
	lifecycleCancel context.CancelFunc
	lifecycleDone   chan struct{}
}

func (r *IdentityRuntime) Close() {
	if r.lifecycleCancel != nil {
		r.lifecycleCancel()
	}
	if r.emailCancel != nil {
		r.emailCancel()
	}
	if r.oidcCancel != nil {
		r.oidcCancel()
	}
	if r.emailCancel != nil {
		<-r.emailDone
	}
	if r.oidcCancel != nil {
		<-r.oidcDone
	}
	if r.lifecycleCancel != nil {
		<-r.lifecycleDone
	}
	if r.Service != nil {
		r.Service.InvitationService().Close()
	}
	r.Email.Close()
	r.Journal.CloseIdleConnections()
	if r.ReleaseLease != nil {
		r.ReleaseLease()
	}
}

// OpenIdentityRuntime never activates a new authority or advances an epoch.
// Activation and supervised restore are explicit CLI operations.
func OpenIdentityRuntime(ctx context.Context, store storage.Store, profile domain.SessionProfile) (*IdentityRuntime, error) {
	if !profile.SecureProfile {
		return nil, errors.New("identity runtime requires the activated secure profile")
	}
	repo, ok := store.(securitystate.Repository)
	if !ok {
		return nil, errors.New("store cannot transact identity state")
	}
	keyFile := os.Getenv("AGP_MFA_KEYRING_FILE")
	if keyFile == "" {
		keyFile = os.Getenv("AGP_MFA_KEY_FILE")
	}
	keys, e := identity.LoadKeyring(keyFile)
	if e != nil {
		return nil, e
	}
	client, e := OpenJournalClient()
	if e != nil {
		return nil, e
	}

	leased, ok := store.(interface {
		AcquireIdentityLease(context.Context) (func(), error)
	})
	if !ok {
		client.CloseIdleConnections()
		return nil, errors.New("secure profile requires a fenced PostgreSQL identity writer")
	}
	releaseLease, e := leased.AcquireIdentityLease(ctx)
	if e != nil {
		client.CloseIdleConnections()
		return nil, e
	}
	opened := false
	defer func() {
		if !opened {
			releaseLease()
		}
	}()
	coordinator := securitystate.New(repo, client)
	nodeidentity.RegisterRecovery(coordinator)
	identity.RegisterDirectoryRecovery(coordinator)
	identity.RegisterEmailRecovery(coordinator)
	directory, connector, e := OpenDirectoryService(coordinator, profile.ManagementOrigin, os.Getenv("AGP_DIRECTORY_CONNECTOR_FILE"))
	if e != nil {
		client.CloseIdleConnections()
		return nil, e
	}
	protected := securitystate.ProtectStore(store, coordinator, profile)
	service, e := identity.New(protected, coordinator, keys, profile)
	if e != nil {
		client.CloseIdleConnections()
		return nil, e
	}
	defer func() {
		if !opened {
			service.InvitationService().Close()
		}
	}()
	service.WithDirectory(directory, connector)
	email, e := OpenEmailService(service, os.Getenv("AGP_EMAIL_CONFIG_FILE"))
	if e != nil {
		client.CloseIdleConnections()
		return nil, e
	}
	defer func() {
		if !opened {
			email.Close()
		}
	}()
	oidc, e := OpenOIDCService(service, os.Getenv("AGP_OIDC_CONNECTOR_FILE"))
	if e != nil {
		client.CloseIdleConnections()
		return nil, e
	}
	if e = coordinator.Recover(ctx); e != nil {
		client.CloseIdleConnections()
		return nil, e
	}
	if e = coordinator.Ready(ctx); e != nil {
		client.CloseIdleConnections()
		return nil, e
	}
	if e = oidc.RecoverAuthorizations(ctx); e != nil {
		client.CloseIdleConnections()
		return nil, e
	}
	if e = service.CleanupLifecycle(ctx); e != nil {
		client.CloseIdleConnections()
		return nil, e
	}
	runtime := &IdentityRuntime{Store: protected, Service: service, Directory: directory, ADConnector: connector, Email: email, OIDC: oidc, Coordinator: coordinator, Journal: client, ReleaseLease: releaseLease}
	if email != nil {
		if e = email.Cleanup(ctx); e != nil {
			client.CloseIdleConnections()
			return nil, e
		}
		workerCtx, cancel := context.WithCancel(ctx)
		runtime.emailCancel, runtime.emailDone = cancel, make(chan struct{})
		go func() {
			defer close(runtime.emailDone)
			RunEmailOutbox(workerCtx, email)
		}()
	}
	workerCtx, cancel := context.WithCancel(ctx)
	runtime.oidcCancel, runtime.oidcDone = cancel, make(chan struct{})
	go func() {
		defer close(runtime.oidcDone)
		_ = oidc.RunCleanup(workerCtx)
	}()
	lifecycleCtx, lifecycleCancel := context.WithCancel(ctx)
	runtime.lifecycleCancel, runtime.lifecycleDone = lifecycleCancel, make(chan struct{})
	go func() { defer close(runtime.lifecycleDone); RunLifecycleOutbox(lifecycleCtx, service) }()
	opened = true
	return runtime, nil
}
