package identity

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

func TestDirectoryHistoricalSubjectsSQLite(t *testing.T)   { testDirectoryHistoricalSubjects(t, false) }
func TestDirectoryHistoricalSubjectsPostgres(t *testing.T) { testDirectoryHistoricalSubjects(t, true) }
func testDirectoryHistoricalSubjects(t *testing.T, pg bool) {
	t.Run("disabled_candidate_is_negative_while_valid_AD_and_local_candidates_remain_usable", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		link := f.provision(t)
		validWire := newADWireFixture(t, "ldaps")
		validWire.config.Spec.ForestGUID = f.provider.ForestGUID
		firstCA := f.wire.connector.secrets.(adFixtureSecrets).ca
		secondCA := validWire.connector.secrets.(adFixtureSecrets).ca
		f.wire.connector.secrets = adFixtureSecrets{ca: append(append([]byte{}, firstCA...), secondCA...)}
		validDoc := f.document
		validDoc.Spec.Endpoints = validWire.config.Spec.Endpoints
		validPrincipal := historicalFixturePrincipalDocument(t, f, 10, validDoc)
		f.wire.disabled.Store(true)
		calls := 0
		e := f.directory.WithCurrentHistoricalSubjects(f.ctx, []string{link.PrincipalID, validPrincipal, f.user.ID}, func(ctx context.Context) error {
			calls++
			return f.s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
				if _, e := DirectorySubjectFingerprint(ctx, tx, h, link.PrincipalID); !errors.Is(e, ErrProof) {
					t.Fatalf("disabled candidate: %v", e)
				}
				if fp, e := DirectorySubjectFingerprint(ctx, tx, h, f.user.ID); e != nil || fp != "" {
					t.Fatalf("valid local candidate: %q %v", fp, e)
				}
				if fp, e := DirectorySubjectFingerprint(ctx, tx, h, validPrincipal); e != nil || fp == "" {
					t.Fatalf("valid AD candidate: %q %v", fp, e)
				}
				return nil
			})
		})
		if e != nil || calls != 1 {
			t.Fatal("candidate search lost valid fallback", e, calls)
		}
		parent, cancel := context.WithCancel(f.ctx)
		defer cancel()
		var captured context.Context
		if e := f.directory.WithCurrentHistoricalSubjects(parent, []string{link.PrincipalID}, func(ctx context.Context) error { captured = ctx; return nil }); e != nil {
			t.Fatal(e)
		}
		if captured == nil || captured.Err() != nil {
			t.Fatal("returned proof context inherited expired batch context")
		}
		if e := f.s.Coordinator.Current(captured, func(tx storage.IdentityTx, h securityjournal.Head) error {
			if _, e := DirectorySubjectFingerprint(captured, tx, h, link.PrincipalID); !errors.Is(e, ErrProof) {
				t.Fatalf("captured negative lost binding: %v", e)
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		cancel()
		if !errors.Is(captured.Err(), context.Canceled) {
			t.Fatal("proof context detached caller cancellation")
		}
		strictCalled := false
		e = f.directory.WithCurrentSubjects(f.ctx, []string{link.PrincipalID}, func(context.Context) error { strictCalled = true; return nil })
		if !errors.Is(e, ErrProof) || strictCalled {
			t.Fatal("strict provider lifecycle swallowed authoritative denial", e)
		}
	})
	t.Run("TLS_failure_is_unavailable_and_never_negative", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		link := f.provision(t)
		f.wire.rejectTLS.Store(true)
		called := false
		e := f.directory.WithCurrentHistoricalSubjects(f.ctx, []string{link.PrincipalID, f.user.ID}, func(context.Context) error { called = true; return nil })
		if !errors.Is(e, ErrDirectoryUnavailable) || called {
			t.Fatal("TLS failure became candidate denial", e, called)
		}
	})
	t.Run("negative_evidence_is_exactly_provider_pinned_and_independent_time_bounded", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		link := f.provision(t)
		f.provider.Revision++
		f.document.Metadata.VersionID = securitystate.ID("dirver")
		f.document.Metadata.SecurityGuardVersion = 2
		f.propose(t)
		f.wire.disabled.Store(true)
		e := f.directory.WithCurrentHistoricalSubjects(f.ctx, []string{link.PrincipalID}, func(ctx context.Context) error {
			if e := f.base.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
				// A trusted fixture publishes a different healthy pin after the network
				// read. Evidence for the old version must never deny/allow the new one.
				_, e := tx.Exec(ctx, `UPDATE directory_providers SET active_version_id=?,guard_version=2,row_version=row_version+1 WHERE id=?`, f.document.Metadata.VersionID, f.provider.ID)
				return e
			}); e != nil {
				return e
			}
			f.wire.disabled.Store(false)
			return f.s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
				if _, e := DirectorySubjectFingerprint(ctx, tx, h, link.PrincipalID); !errors.Is(e, ErrDirectoryUnavailable) {
					t.Fatalf("old negative accepted for successor pin: %v", e)
				}
				return nil
			})
		})
		if e != nil {
			t.Fatal(e)
		}
		f.wire.disabled.Store(true)
		e = f.directory.WithCurrentHistoricalSubjects(f.ctx, []string{link.PrincipalID}, func(ctx context.Context) error {
			f.clock(f.now.Add(11 * time.Second))
			return f.s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
				if _, e := DirectorySubjectFingerprint(ctx, tx, h, link.PrincipalID); !errors.Is(e, ErrDirectoryUnavailable) {
					t.Fatalf("expired independent-time negative reused: %v", e)
				}
				return nil
			})
		})
		if e != nil {
			t.Fatal(e)
		}
	})
	t.Run("bounded_pool_three_and_input_256", func(t *testing.T) {
		f := newDirectoryAuthFixture(t, pg, false)
		link := f.provision(t)
		ids := []string{link.PrincipalID}
		for i := 0; i < 3; i++ {
			ids = append(ids, historicalFixturePrincipal(t, f, i))
		}
		counter := &historicalCountingSecrets{delegate: f.wire.connector.secrets, gate: make(chan struct{}), ready: make(chan struct{})}
		f.wire.connector.secrets = counter
		complete := make(chan error, 1)
		go func() {
			complete <- f.directory.WithCurrentHistoricalSubjects(f.ctx, ids, func(ctx context.Context) error {
				return f.s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
					for _, id := range ids {
						fp, e := DirectorySubjectFingerprint(ctx, tx, h, id)
						if e != nil {
							return fmt.Errorf("positive historical proof %s: %w", id, e)
						}
						if fp == "" {
							return errors.New("empty positive directory fingerprint")
						}
					}
					return nil
				})
			})
		}()
		select {
		case <-counter.ready:
		case <-time.After(3 * time.Second):
			close(counter.gate)
			<-complete
			t.Fatal("historical workers never reached resolver")
		}
		time.Sleep(20 * time.Millisecond)
		close(counter.gate)
		if e := <-complete; e != nil {
			t.Fatal(e)
		}
		if maximum := counter.maximum.Load(); maximum != 3 || counter.active.Load() != 0 {
			t.Fatalf("pool not bounded/joined: maximum=%d active=%d", maximum, counter.active.Load())
		}
		cancelProbe := &historicalCancellingSecrets{ready: make(chan struct{})}
		f.wire.connector.secrets = cancelProbe
		called := false
		e := f.directory.WithCurrentHistoricalSubjects(f.ctx, ids, func(context.Context) error { called = true; return nil })
		if !errors.Is(e, ErrDirectoryUnavailable) || called || cancelProbe.active.Load() != 0 {
			t.Fatalf("infra error did not cancel/join all workers: %v called=%v active=%d", e, called, cancelProbe.active.Load())
		}
		locals := make([]string, 256)
		for i := range locals {
			locals[i] = f.user.ID
		}
		if e := f.directory.WithCurrentHistoricalSubjects(f.ctx, locals, func(context.Context) error { return nil }); e != nil {
			t.Fatal("valid bounded local input rejected", e)
		}
		locals = append(locals, f.user.ID)
		if e := f.directory.WithCurrentHistoricalSubjects(f.ctx, locals, func(context.Context) error { t.Fatal("oversized batch callback"); return nil }); !errors.Is(e, ErrDirectoryInvalid) {
			t.Fatal("input bound missing", e)
		}
	})
}

type historicalCountingSecrets struct {
	delegate                 DirectorySecretResolver
	active, maximum, started atomic.Int64
	gate, ready              chan struct{}
	once                     sync.Once
}

func (s *historicalCountingSecrets) ResolveDirectorySecrets(ctx context.Context, bind, ca string) (DirectorySecrets, error) {
	active := s.active.Add(1)
	defer s.active.Add(-1)
	for {
		old := s.maximum.Load()
		if active <= old || s.maximum.CompareAndSwap(old, active) {
			break
		}
	}
	if s.started.Add(1) == 3 {
		s.once.Do(func() { close(s.ready) })
	}
	select {
	case <-s.gate:
	case <-ctx.Done():
		return DirectorySecrets{}, ctx.Err()
	}
	return s.delegate.ResolveDirectorySecrets(ctx, bind, ca)
}
func historicalFixturePrincipal(t *testing.T, f *directoryAuthFixture, n int) string {
	t.Helper()
	return historicalFixturePrincipalDocument(t, f, n, f.document)
}
func historicalFixturePrincipalDocument(t *testing.T, f *directoryAuthFixture, n int, doc DirectoryProviderDocument) string {
	t.Helper()
	id := fmt.Sprintf("historical_principal_%d", n)
	provider := fmt.Sprintf("dir_historical_%d", n)
	version := fmt.Sprintf("dirver_historical_%d", n)
	guard := fmt.Sprintf("guard_historical_%d", n)
	link := fmt.Sprintf("link_historical_%d", n)
	doc.Metadata = DirectoryMetadata{ID: provider, VersionID: version, SecurityGuardID: guard, SecurityGuardVersion: 1}
	canonical, e := configmodel.CanonicalJSON(doc)
	if e != nil {
		t.Fatal(e)
	}
	digest, e := configmodel.Digest(doc)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.base.WriteIdentity(f.ctx, func(tx storage.IdentityTx) error {
		if _, e := tx.Exec(f.ctx, `INSERT INTO users(id,username,password_hash,identity_kind,security_version,password_version) VALUES(?,?,'','directory',1,1)`, id, id); e != nil {
			return e
		}
		if _, e := tx.Exec(f.ctx, `INSERT INTO directory_providers(id,name,forest_guid,guard_id,row_version,guard_version,enabled,active_version_id,created_at) VALUES(?,?,?,?,1,1,TRUE,?,?)`, provider, provider, doc.Spec.ForestGUID, guard, version, f.now); e != nil {
			return e
		}
		if _, e := tx.Exec(f.ctx, `INSERT INTO directory_provider_versions(id,provider_id,guard_version,content_digest,canonical_json,author_id,author_fingerprint,created_at) VALUES(?,?,1,?,?,?,?,?)`, version, provider, digest, string(canonical), f.user.ID, "unused fixture author fingerprint", f.now); e != nil {
			return e
		}
		_, e := tx.Exec(f.ctx, `INSERT INTO directory_identities(id,principal_id,provider_id,forest_guid,object_guid,authenticator_version,revoked,created_at) VALUES(?,?,?,?,?,1,FALSE,?)`, link, id, provider, doc.Spec.ForestGUID, "20112233-4455-6677-8899-aabbccddeeff", f.now)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	return id
}

func TestDirectoryManagementProofRefreshSQLite(t *testing.T) {
	testDirectoryManagementProofRefresh(t, false)
}
func TestDirectoryManagementProofRefreshPostgres(t *testing.T) {
	testDirectoryManagementProofRefresh(t, true)
}
func testDirectoryManagementProofRefresh(t *testing.T, pg bool) {
	f := newDirectoryAuthFixture(t, pg, false)
	link, actor := f.managementDirectory(t)
	var old context.Context
	if e := f.s.WithCurrentSession(f.ctx, actor.TokenHash, "management", actor.Origin, func(ctx context.Context, _ *domain.SessionContext) error { old = ctx; return nil }); e != nil {
		t.Fatal(e)
	}
	f.clock(f.now.Add(11 * time.Second))
	guard := func(ctx context.Context) error {
		return f.s.Coordinator.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
			return f.s.Coordinator.CheckManagementSession(ctx, tx, h, actor.TokenHash)
		})
	}
	if e := guard(old); !errors.Is(e, ErrDirectoryUnavailable) {
		t.Fatal("old HTTP proof did not expire", e)
	}
	probe := &historicalWriterProbeSecrets{delegate: f.wire.connector.secrets, store: f.base}
	f.wire.connector.secrets = probe
	e := f.s.Coordinator.WithManagementSession(old, actor.TokenHash, func(fresh context.Context) error {
		if e := guard(fresh); e != nil {
			return fmt.Errorf("fresh proof rejected: %w", e)
		}
		if e := guard(old); !errors.Is(e, ErrDirectoryUnavailable) {
			t.Fatalf("refresh silently mutated old request proof: %v", e)
		}
		return nil
	})
	probe.workers.Wait()
	if e != nil || probe.checked.Load() == 0 {
		t.Fatal("refresh held writer during live network boundary", e, probe.checked.Load())
	}
	e = f.s.Coordinator.WithManagementSession(old, actor.TokenHash, func(fresh context.Context) error {
		if e := f.directory.RevokeIdentity(f.ctx, f.author, f.provider.ID, link.ID, "Revoke after refreshed live check before final writer"); e != nil {
			return e
		}
		if e := guard(fresh); e == nil {
			t.Fatal("link changed after refresh bypassed final current check")
		}
		return nil
	})
	probe.workers.Wait()
	if e != nil {
		t.Fatal(e)
	}
}

type historicalWriterProbeSecrets struct {
	delegate DirectorySecretResolver
	store    storage.Store
	workers  sync.WaitGroup
	checked  atomic.Int64
}

func (s *historicalWriterProbeSecrets) ResolveDirectorySecrets(ctx context.Context, bind, ca string) (DirectorySecrets, error) {
	done := make(chan error, 1)
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		done <- s.store.WriteIdentity(ctx, func(tx storage.IdentityTx) error {
			var value int
			return securitystate.One(ctx, tx, `SELECT 1`, nil, func(row storage.IdentityRows) error { return row.Scan(&value) })
		})
	}()
	select {
	case e := <-done:
		if e != nil {
			return DirectorySecrets{}, e
		}
		s.checked.Add(1)
	case <-ctx.Done():
		return DirectorySecrets{}, ctx.Err()
	}
	return s.delegate.ResolveDirectorySecrets(ctx, bind, ca)
}

// One failing resolver waits until all three workers have started; its siblings
// cannot finish until cancellation. Returning from the batch must join all of
// them rather than leaving detached credential/network work behind.
type historicalCancellingSecrets struct {
	started, active atomic.Int64
	ready           chan struct{}
}

func (s *historicalCancellingSecrets) ResolveDirectorySecrets(ctx context.Context, _, _ string) (DirectorySecrets, error) {
	s.active.Add(1)
	defer s.active.Add(-1)
	order := s.started.Add(1)
	if order == 3 {
		close(s.ready)
	}
	if order == 1 {
		select {
		case <-s.ready:
			return DirectorySecrets{}, errors.New("synthetic secret infrastructure failure")
		case <-ctx.Done():
			return DirectorySecrets{}, ctx.Err()
		}
	}
	<-ctx.Done()
	return DirectorySecrets{}, ctx.Err()
}
