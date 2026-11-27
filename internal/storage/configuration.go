package storage

import "context"

var ErrConfigurationReadOnly = errString("configuration_revision_required")

// RequireLegacyResourceWrites is checked before a durable legacy intent exists.
// Database triggers provide a second fence for direct SQL/current-version tools.
func RequireLegacyResourceWrites(ctx context.Context, tx IdentityTx) error {
	rows, err := tx.Query(ctx, `SELECT enabled FROM configuration_profile WHERE id=1`)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return err
		}
		return ErrNotFound
	}
	var enabled bool
	if err = rows.Scan(&enabled); err != nil {
		return err
	}
	if enabled {
		return ErrConfigurationReadOnly
	}
	return rows.Err()
}
