//go:build linux

package nativeactivation

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"golang.org/x/sys/unix"
)

// reconcilePointers runs under the installation lock before accepting work.
// A reboot may leave either side of an atomic exchange under its random name.
// Only a closed, exact durable base/target record can prove such a name ours.
func (d *Driver) reconcilePointers(ctx context.Context) error {
	all, e := names(d.root.file(), 20)
	if e != nil {
		return e
	}
	stable := map[string]bool{"active": false, "generations": false, "native.lock": false, "recovery": false}
	var pending []string
	for _, name := range all {
		if _, ok := stable[name]; ok {
			stable[name] = true
			continue
		}
		raw := strings.TrimPrefix(name, ".active-")
		decoded, de := hex.DecodeString(raw)
		if !strings.HasPrefix(name, ".active-") || de != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != raw {
			return ErrTree
		}
		pending = append(pending, name)
	}
	for _, present := range stable {
		if !present {
			return ErrTree
		}
	}
	if len(pending) == 0 {
		return nil
	}
	active, e := d.active(ctx)
	if e != nil {
		return e
	}
	recordNames, e := names(d.recovery, helper.MaxExecutionRecords)
	if e != nil {
		return e
	}
	type verifiedTemp struct {
		name string
		pin  unix.Stat_t
	}
	var verified []verifiedTemp
	for _, name := range pending {
		var pin unix.Stat_t
		if unix.Fstatat(int(d.root.file().Fd()), name, &pin, unix.AT_SYMLINK_NOFOLLOW) != nil || pin.Mode&unix.S_IFMT != unix.S_IFLNK || pin.Uid != d.owner {
			return ErrTree
		}
		mount, me := namedMountID(d.root.file(), name)
		rootMount, re := mountID(int(d.root.file().Fd()))
		if me != nil || re != nil || mount != rootMount {
			return ErrTree
		}
		buf := make([]byte, 256)
		n, e := unix.Readlinkat(int(d.root.file().Fd()), name, buf)
		if e != nil || n == len(buf) {
			return ErrTree
		}
		parts := strings.Split(string(buf[:n]), "/")
		if len(parts) != 3 || parts[0] != "generations" || parts[2] != "tree" || !configmodel.ValidID(parts[1]) {
			return ErrTree
		}
		tempID := parts[1]
		proved := false
		for _, recordName := range recordNames {
			if !strings.HasSuffix(recordName, ".json") || !configmodel.ValidID(strings.TrimSuffix(recordName, ".json")) {
				return ErrTree
			}
			var record recoveryRecord
			if _, e = canonicalRead(d.recovery, recordName, maxMetadata, d.owner, &record); e != nil {
				return e
			}
			if record.APIVersion != Version || recordName != storageSlot(record.Target)+".json" {
				return ErrTree
			}
			opposite := storageSlot(record.Base) == tempID && record.Target == active.Generation || storageSlot(record.Target) == tempID && record.Base == active.Generation
			if !opposite {
				continue
			}
			if _, e = d.load(ctx, record.Base); e != nil {
				return e
			}
			if _, e = d.load(ctx, record.Target); e != nil {
				return e
			}
			proved = true
			break
		}
		if !proved {
			return ErrTree
		}
		verified = append(verified, verifiedTemp{name, pin})
	}
	// Verify every candidate first. Unknown entries cause no cleanup at all.
	for _, v := range verified {
		var now unix.Stat_t
		if unix.Fstatat(int(d.root.file().Fd()), v.name, &now, unix.AT_SYMLINK_NOFOLLOW) != nil || !fullSame(v.pin, now) || unix.Unlinkat(int(d.root.file().Fd()), v.name, 0) != nil {
			return ErrTree
		}
	}
	if d.root.file().Sync() != nil {
		return ErrTree
	}
	return exactNames(d.root.file(), []string{"active", "generations", "native.lock", "recovery"})
}
