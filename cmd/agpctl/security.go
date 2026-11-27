package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/netwizd/agp/internal/auth"
	"github.com/netwizd/agp/internal/config"
	"github.com/netwizd/agp/internal/runtime"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/securitystate"
)

// securityState deliberately splits the externally fenced restore epoch from
// CP replay. A restored CP database cannot authorize or erase its own barrier.
func securityState(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agpctl security-state {head|prepare-restore|append-approved|replay|ready}")
	}
	command := args[0]
	flags := flag.NewFlagSet("security-state "+command, flag.ContinueOnError)
	actor := flags.String("actor", "", "operator principal ID")
	fenced := flags.Bool("writers-fenced", false, "confirm all previous CP writers are stopped and fenced")
	fencedAt := flags.String("writer-fenced-at", "", "trusted end of old writer lifetime (RFC3339Nano)")
	skew := flags.String("max-clock-skew", "", "verified maximum clock skew, e.g. 2s")
	requestFile := flags.String("request", "", "independently approved request JSON")
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	client, e := runtime.OpenJournalClient()
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	switch command {
	case "head":
		h, e := client.Head(ctx)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(h)
	case "prepare-restore":
		if !*fenced || *actor == "" || *fencedAt == "" || *skew == "" {
			return errors.New("prepare-restore requires --writers-fenced, --writer-fenced-at, --max-clock-skew and --actor; fence old writers before preparing")
		}
		end, e := time.Parse(time.RFC3339Nano, *fencedAt)
		if e != nil {
			return errors.New("invalid writer-fenced-at")
		}
		bound, e := time.ParseDuration(*skew)
		if e != nil || bound < 0 || bound > 5*time.Minute {
			return errors.New("max-clock-skew must be a verified duration between 0s and 5m")
		}
		now := time.Now().UTC()
		if end.After(now) || end.Before(now.Add(-5*time.Minute)) {
			return errors.New("writer fencing evidence must be fresh (within 5m); reconfirm fencing before preparing")
		}
		head, e := client.Head(ctx)
		if e != nil {
			return e
		}
		token, _, e := auth.NewToken()
		if e != nil {
			return e
		}
		cutoff := end.UTC().Truncate(time.Microsecond)
		req := securityjournal.AppendRequest{OperationID: "restore_" + token, ExpectedEpoch: head.Epoch, ExpectedSequence: head.Sequence, ExpectedDigest: head.Digest, Kind: "advance_authority_epoch", TargetType: "authority", TargetID: head.AuthorityID, ActorID: *actor, RecordedAt: now, Payload: securityjournal.Payload{NewEpoch: head.Epoch + 1, RestoreCutoff: cutoff, ReleaseAfter: cutoff.Add(90*time.Second + bound + time.Second)}}
		req.AuthorizationDigest = securitystate.Digest(struct {
			Reason         string
			Actor          string
			WriterFencedAt time.Time
			MaxClockSkew   string
		}{"supervised CP restore", *actor, cutoff, bound.String()})
		return json.NewEncoder(os.Stdout).Encode(req)
	case "append-approved":
		if *requestFile == "" {
			return errors.New("append-approved requires --request FILE")
		}
		req, e := readJournalRequest(*requestFile)
		if e != nil {
			return e
		}
		if req.ApprovalSignature == "" || req.ApprovalKeyID == "" || req.ApproverID == "" || req.ApproverID == req.ActorID {
			return errors.New("independent signed approval is required")
		}
		switch req.Kind {
		case "advance_authority_epoch", "unblock_principal", "enable_resource", "clear_route_deny":
		default:
			return errors.New("append-approved accepts restore or referenced deny lifts only")
		}
		ev, e := client.Append(ctx, req)
		if e != nil {
			// Resolve a possibly committed response before deciding the operation failed.
			saved, lookup := client.Operation(ctx, req.OperationID)
			if lookup != nil {
				return e
			}
			digest, de := securityjournal.RequestDigest(req)
			if de != nil || saved.RequestDigest != digest {
				return securityjournal.ErrConflict
			}
			ev = saved
		}
		return json.NewEncoder(os.Stdout).Encode(ev)
	case "replay", "ready":
		cfg, e := config.Load()
		if e != nil {
			return e
		}
		if cfg.DatabaseDriver != "postgres" {
			return errors.New("secure restore requires PostgreSQL control-plane storage")
		}
		store, e := runtime.OpenStore(ctx, cfg)
		if e != nil {
			return e
		}
		defer store.Close()
		repo, ok := store.(securitystate.Repository)
		if !ok {
			return errors.New("store does not support security-state transactions")
		}

		if command == "replay" {
			leased, ok := store.(interface {
				AcquireIdentityLease(context.Context) (func(), error)
			})
			if !ok {
				return errors.New("restore replay requires a fenced PostgreSQL writer")
			}
			release, e := leased.AcquireIdentityLease(ctx)
			if e != nil {
				return e
			}
			defer release()
		}
		coordinator := securitystate.New(repo, client)
		if command == "replay" {
			if e = coordinator.Replay(ctx); e != nil {
				return e
			}
			fmt.Fprintln(os.Stdout, "restrictive journal replay completed; check readiness after recovery and quarantine")
			return nil
		}
		if e = coordinator.Ready(ctx); e != nil {
			return e
		}
		fmt.Fprintln(os.Stdout, "security state is current and restore quarantine has elapsed")
		return nil
	default:
		return errors.New("unknown security-state command")
	}
}
func readJournalRequest(file string) (securityjournal.AppendRequest, error) {
	var r securityjournal.AppendRequest
	f, e := os.Open(file)
	if e != nil {
		return r, e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 262145))
	d.DisallowUnknownFields()
	if e = d.Decode(&r); e != nil {
		return r, errors.New("invalid journal request JSON")
	}
	if e = d.Decode(new(any)); e != io.EOF {
		return r, errors.New("trailing journal request JSON")
	}
	return r, nil
}
