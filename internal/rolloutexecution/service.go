package rolloutexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
	"github.com/netwizd/agp/internal/storage"
)

const MaxPlanTTL = 30 * time.Minute

var requestKey = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

type Service struct {
	current  Current
	sources  Sources
	keys     Keys
	origin   string
	subjects DirectorySubjects
	agents   AgentAuthenticator
}

func New(current Current, sources Sources, keys Keys, origin string) (*Service, error) {
	u, err := url.Parse(origin)
	if current == nil || sources == nil || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || origin != "https://"+u.Host || !configmodel.ValidID(keys.PermitKeyID) || !configmodel.ValidID(keys.ControlKeyID) || keys.PermitKeyID == keys.ControlKeyID || len(keys.PermitKey) != ed25519.PrivateKeySize || len(keys.ControlKey) != ed25519.PrivateKeySize || bytes.Equal(keys.PermitKey.Public().(ed25519.PublicKey), keys.ControlKey.Public().(ed25519.PublicKey)) {
		return nil, ErrUnavailable
	}
	keys.PermitKey = append(ed25519.PrivateKey(nil), keys.PermitKey...)
	keys.ControlKey = append(ed25519.PrivateKey(nil), keys.ControlKey...)
	return &Service{current: current, sources: sources, keys: keys, origin: origin}, nil
}

// These dependencies are registered before serving requests.
func (s *Service) WithDirectorySubjects(v DirectorySubjects) *Service   { s.subjects = v; return s }
func (s *Service) WithAgentAuthenticator(v AgentAuthenticator) *Service { s.agents = v; return s }

func canonical(v any) ([]byte, error) { return configmodel.CanonicalJSON(v) }
func digest(v any) string             { d, _ := configmodel.Digest(v); return d }
func utc(t time.Time) string          { return t.UTC().Format(time.RFC3339Nano) }
func parseTime(v string) time.Time    { t, _ := time.Parse(time.RFC3339Nano, v); return t }
func unique(ids []string) []string {
	out := append([]string{}, ids...)
	sort.Strings(out)
	return slicesUnique(out)
}
func slicesUnique(ids []string) []string {
	out := ids[:0]
	for _, id := range ids {
		if len(out) == 0 || out[len(out)-1] != id {
			out = append(out, id)
		}
	}
	return out
}
func (s *Service) withSubjects(ctx context.Context, ids []string, fn func(context.Context) error) error {
	if s.subjects == nil {
		return fn(ctx)
	}
	return s.subjects.WithCurrentHistoricalSubjects(ctx, unique(ids), fn)
}

type storedPlan struct {
	view               ExecutionPlan
	snapshot           Snapshot
	creatorFingerprint string
}

func readPlan(ctx context.Context, tx storage.IdentityTx, id string) (*storedPlan, error) {
	var raw, snapshot, pin string
	p := &storedPlan{}
	err := securitystate.One(ctx, tx, `SELECT plan_json,snapshot_json,plan_digest,creator_fingerprint,COALESCE(parent_plan_id,''),state FROM execution_plans WHERE id=?`, []any{id}, func(r storage.IdentityRows) error {
		return r.Scan(&raw, &snapshot, &pin, &p.creatorFingerprint, &p.view.ParentPlanID, &p.view.State)
	})
	if err != nil {
		return nil, err
	}
	if len(raw) > 2097152 || len(snapshot) > 4194304 || json.Unmarshal([]byte(raw), &p.view.Plan) != nil || json.Unmarshal([]byte(snapshot), &p.snapshot) != nil || p.view.Plan.ID != id || p.view.Plan.PlanDigest != pin || deploymentDigest(p) != nil {
		return nil, ErrUnavailable
	}
	p.view.Tasks = []TaskView{}
	return p, nil
}
func deploymentDigest(p *storedPlan) error {
	if err := verifyPlan(p.view.Plan); err != nil {
		return err
	}
	for _, in := range p.view.Plan.ResolvedInputs {
		if in.Kind == "assignment_resolution" && in.ID == "execution_sources" && in.Digest == digest(p.snapshot) {
			return nil
		}
	}
	return ErrUnavailable
}
func (p *storedPlan) target(node string) (TargetSnapshot, error) {
	for _, target := range p.snapshot.Targets {
		if target.Installation.NodeID == node {
			return target, nil
		}
	}
	return TargetSnapshot{}, storage.ErrNotFound
}
func (p *storedPlan) participants() []string {
	return unique(append(append([]string{}, p.snapshot.Authors...), p.view.Plan.CreatedBy))
}
func request(ctx context.Context, tx storage.IdentityTx, actor, operation, key, fp string) (string, error) {
	if !requestKey.MatchString(key) {
		return "", ErrInvalid
	}
	var found, pin string
	err := securitystate.One(ctx, tx, `SELECT result_id,fingerprint FROM execution_requests WHERE actor_id=? AND operation=? AND request_key=?`, []any{actor, operation, key}, func(r storage.IdentityRows) error { return r.Scan(&found, &pin) })
	if err == storage.ErrNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if pin != fp {
		return "", ErrConflict
	}
	return found, nil
}
func remember(ctx context.Context, tx storage.IdentityTx, actor, operation, key, fp, id string, at time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO execution_requests(actor_id,operation,request_key,fingerprint,result_id,created_at) VALUES(?,?,?,?,?,?)`, actor, operation, key, fp, id, at)
	return err
}
func audit(ctx context.Context, tx storage.IdentityTx, kind, actor, id string) error {
	return securitystate.Audit(ctx, tx, kind, actor, map[string]any{"executionPlanId": id})
}
func checkNode(ctx context.Context, tx storage.IdentityTx, id string) error {
	ids, err := securitystate.Strings(ctx, tx, `SELECT node_id FROM security_node_revocations WHERE node_id=?`, id)
	if err != nil {
		return err
	}
	if len(ids) != 0 {
		return storage.ErrPermissionDenied
	}
	return nil
}
func (s *Service) selectParticipants(ctx context.Context, a Actor, id string) ([]string, error) {
	var ids []string
	err := securitystate.WithManagementSession(ctx, a.TokenHash, s.current, func(fresh context.Context) error {
		return s.current.Current(fresh, func(tx storage.IdentityTx, h securityjournal.Head) error {
			actor, err := s.actor(fresh, tx, h, a, false)
			if err != nil {
				return err
			}
			p, err := readPlan(fresh, tx, id)
			if err != nil {
				return err
			}
			if !covers(actor.grants, "config.read", p.snapshot.Targets) {
				return storage.ErrNotFound
			}
			ids = p.participants()
			approval, _, err := readApproval(fresh, tx, id)
			if err != nil && err != storage.ErrNotFound {
				return err
			}
			if approval != nil {
				ids = append(ids, approval.ApprovedBy)
			}
			var dispatcher string
			err = securitystate.One(fresh, tx, `SELECT dispatcher_id FROM execution_rollouts WHERE plan_id=?`, []any{id}, func(r storage.IdentityRows) error { return r.Scan(&dispatcher) })
			if err != nil && err != storage.ErrNotFound {
				return err
			}
			if dispatcher != "" {
				ids = append(ids, dispatcher)
			}
			return nil
		})
	})
	return ids, err
}
func (s *Service) transact(ctx context.Context, a Actor, ids []string, write bool, fn func(*operation) error) error {
	if s == nil || s.current == nil || s.sources == nil || a.Origin != s.origin || a.TokenHash == "" {
		return storage.ErrPermissionDenied
	}
	return securitystate.WithManagementSession(ctx, a.TokenHash, s.current, func(authenticated context.Context) error {
		return s.withSubjects(authenticated, ids, func(fresh context.Context) error {
			return s.current.Current(fresh, func(tx storage.IdentityTx, h securityjournal.Head) error {
				actor, err := s.actor(fresh, tx, h, a, write)
				if err != nil {
					return err
				}
				o := newOperation(s, fresh, tx, h)
				o.actor = actor
				o.credentials = &a
				o.write = write
				if err = fn(o); err != nil {
					return err
				}
				return o.finish()
			})
		})
	})
}

func (s *Service) peerOperation(ctx context.Context, peer *tls.ConnectionState, ids []string, fn func(*operation, string) error) error {
	if s == nil || s.agents == nil || peer == nil {
		return storage.ErrPermissionDenied
	}
	return s.withSubjects(ctx, ids, func(fresh context.Context) error {
		return s.current.Current(fresh, func(tx storage.IdentityTx, h securityjournal.Head) error {
			node, err := s.agents(fresh, tx, h, peer)
			if err != nil {
				return err
			}
			if !configmodel.ValidID(node) {
				return storage.ErrPermissionDenied
			}
			o := newOperation(s, fresh, tx, h)
			o.peer = peer
			o.peerNode = node
			if err = fn(o, node); err != nil {
				return err
			}
			return o.finish()
		})
	})
}
func unexpected(err error) error { return fmt.Errorf("%w: %v", ErrUnavailable, err) }
