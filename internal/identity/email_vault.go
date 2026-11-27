package identity

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/netwizd/agp/internal/securitystate"
)

type emailVaultEntry struct {
	key     []byte
	expires time.Time
	timer   *time.Timer
}

// emailVault is deliberately volatile. No wrapped DEK or recovery material is
// stored in PostgreSQL, so restoring its backup cannot revive queued plaintext.
type emailVault struct {
	mu       sync.Mutex
	entries  map[string]emailVaultEntry
	capacity int
	closed   bool
}

func newEmailVault(capacity int) *emailVault {
	return &emailVault{entries: map[string]emailVaultEntry{}, capacity: capacity}
}
func (v *emailVault) sweepLocked(now time.Time) {
	for id, e := range v.entries {
		if !now.Before(e.expires) {
			clear(e.key)
			e.timer.Stop()
			delete(v.entries, id)
		}
	}
}
func (v *emailVault) put(now, expires time.Time) (string, []byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweepLocked(now)
	if v.closed || !now.Before(expires) || expires.Sub(now) > 5*time.Minute || len(v.entries) >= v.capacity {
		return "", nil, ErrEmailUnavailable
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return "", nil, ErrEmailUnavailable
	}
	id := securitystate.ID("mail_key")
	entry := emailVaultEntry{key: append([]byte(nil), key...), expires: expires}
	entry.timer = time.AfterFunc(expires.Sub(now), func() { v.drop(id) })
	v.entries[id] = entry
	return id, key, nil
}
func (v *emailVault) take(id string, now time.Time) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweepLocked(now)
	e, ok := v.entries[id]
	if !ok || v.closed {
		return nil, ErrEmailUnavailable
	}
	delete(v.entries, id)
	e.timer.Stop()
	return e.key, nil
}
func (v *emailVault) has(id string, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweepLocked(now)
	_, ok := v.entries[id]
	return ok && !v.closed
}
func (v *emailVault) drop(id string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if e, ok := v.entries[id]; ok {
		clear(e.key)
		e.timer.Stop()
		delete(v.entries, id)
	}
}
func (v *emailVault) sweep(now time.Time) { v.mu.Lock(); defer v.mu.Unlock(); v.sweepLocked(now) }
func (v *emailVault) close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closed = true
	for id, e := range v.entries {
		clear(e.key)
		e.timer.Stop()
		delete(v.entries, id)
	}
}
