package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func directoryPreMigrationDB(t *testing.T) *sql.DB {
	t.Helper()
	db, e := sql.Open("sqlite", filepath.Join(t.TempDir(), "upgrade.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	files, e := filepath.Glob("../storage/sqlite/migrations/*.sql")
	if e != nil {
		t.Fatal(e)
	}
	sort.Strings(files)
	for _, name := range files {
		if filepath.Base(name) >= "025_" {
			break
		}
		raw, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(string(raw)); e != nil {
			t.Fatalf("old migration %s: %v", filepath.Base(name), e)
		}
	}
	statements := []string{
		`INSERT INTO users(id,username,password_hash,display_name,is_admin,security_version,password_version) VALUES('upgrade_user','upgrade-user','opaque-hash','Upgrade',TRUE,9,7)`,
		`INSERT INTO resources(id,name,internal_url,public_host,enabled) VALUES('upgrade_resource','Upgrade','http://127.0.0.1:9999','upgrade.agp.test',TRUE)`,
		`INSERT INTO gateways(id,node_id,origin,callback,resource_id,generation,enabled) VALUES('upgrade_gateway','upgrade_node','https://upgrade.agp.test','https://upgrade.agp.test/_agp/callback','upgrade_resource','upgrade_generation',TRUE)`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,revoked_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at,source_session_id,gateway_id,node_id) VALUES('legacy_session','upgrade_user','legacy-token','legacy-csrf','192.0.2.1','legacy-agent','2027-01-01 00:00:00','2026-01-01 00:00:00','2026-02-01 00:00:00','legacy','',3,9,'2026-01-01 00:00:00','2026-01-01 00:10:00','','','')`,
		`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at,source_session_id,gateway_id,node_id) VALUES('management_session','upgrade_user','management-token','management-csrf','192.0.2.2','management-agent','2027-01-01 00:00:00','2026-01-01 00:00:00','management','https://management.agp.test',3,9,'2026-01-01 00:00:00','2026-01-01 00:10:00','legacy_session','upgrade_gateway','upgrade_node')`,
		`INSERT INTO handoffs(code_hash,gateway_id,node_id,redirect_uri,challenge,source_session_id,principal_id,security_version,epoch,expires_at) VALUES('upgrade-code','upgrade_gateway','upgrade_node','https://upgrade.agp.test/_agp/callback','upgrade-challenge','management_session','upgrade_user',9,3,'2027-01-01 00:00:00')`,
		`INSERT INTO authenticator_floors(principal_id,authenticator_id,minimum_version) VALUES('upgrade_user','principal_upgrade_user',9)`,
		`INSERT INTO schema_migrations(version) VALUES('rollback-sentinel')`,
	}
	for _, statement := range statements {
		if _, e = db.Exec(statement); e != nil {
			t.Fatal(e)
		}
	}
	return db
}
func directoryMigrationSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	columns := `id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,revoked_at,audience,audience_origin,authority_epoch,security_version,mfa_at,last_seen_at,source_session_id,gateway_id,node_id`
	rows, e := db.Query(`SELECT ` + columns + ` FROM sessions ORDER BY id`)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	var all [][]any
	for rows.Next() {
		values := make([]any, 18)
		refs := make([]any, 18)
		for i := range values {
			refs[i] = &values[i]
		}
		if e = rows.Scan(refs...); e != nil {
			t.Fatal(e)
		}
		all = append(all, values)
	}
	if e = rows.Err(); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(all)
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}
func directoryMigrationApply(t *testing.T, db *sql.DB, fail bool) error {
	t.Helper()
	raw, e := os.ReadFile("../storage/sqlite/migrations/025_directory_auth.sql")
	if e != nil {
		t.Fatal(e)
	}
	script := string(raw)
	if fail {
		script = strings.Replace(script, "DROP TABLE sessions;", "DROP TABLE sessions;\nINSERT INTO schema_migrations(version) VALUES('rollback-sentinel');", 1)
	}
	tx, e := db.BeginTx(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec(script); e != nil {
		return e
	}
	return tx.Commit()
}
func TestDirectorySQLiteSessionUpgrade(t *testing.T) {
	t.Run("preserves_sessions_handoffs_floors_indexes_and_foreign_keys", func(t *testing.T) {
		db := directoryPreMigrationDB(t)
		before := directoryMigrationSnapshot(t, db)
		if e := directoryMigrationApply(t, db, false); e != nil {
			t.Fatal(e)
		}
		if after := directoryMigrationSnapshot(t, db); after != before {
			t.Fatalf("session metadata changed\nbefore %s\nafter %s", before, after)
		}
		var source string
		if e := db.QueryRow(`SELECT source_session_id FROM handoffs WHERE code_hash='upgrade-code'`).Scan(&source); e != nil || source != "management_session" {
			t.Fatal("handoff source changed", e)
		}
		var floor int
		if e := db.QueryRow(`SELECT minimum_version FROM authenticator_floors WHERE principal_id='upgrade_user'`).Scan(&floor); e != nil || floor != 9 {
			t.Fatal("floor changed", e)
		}
		for _, index := range []string{"idx_sessions_token_hash", "idx_sessions_user_id", "idx_sessions_expires_at"} {
			var n int
			if e := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND tbl_name='sessions' AND name=?`, index).Scan(&n); e != nil || n != 1 {
				t.Fatal("session index lost", index, e)
			}
		}
		for _, audience := range []string{"login", "gateway"} {
			if _, e := db.Exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,?)`, audience, "upgrade_user", audience+"-token", "csrf", "127.0.0.1", "test", audience); e != nil {
				t.Fatal("new audience rejected", audience, e)
			}
		}
		rows, e := db.Query(`PRAGMA foreign_key_check`)
		if e != nil {
			t.Fatal(e)
		}
		defer rows.Close()
		if rows.Next() {
			t.Fatal("foreign-key corruption after rebuild")
		}
	})
	t.Run("failure_after_drop_rolls_back_schema_and_all_rows", func(t *testing.T) {
		db := directoryPreMigrationDB(t)
		before := directoryMigrationSnapshot(t, db)
		if e := directoryMigrationApply(t, db, true); e == nil {
			t.Fatal("injected failure did not fail")
		}
		if after := directoryMigrationSnapshot(t, db); after != before {
			t.Fatal("partial session migration escaped rollback")
		}
		var n int
		if e := db.QueryRow(`SELECT count(*) FROM pragma_table_info('users') WHERE name='identity_kind'`).Scan(&n); e != nil || n != 0 {
			t.Fatal("partial user schema escaped rollback", e)
		}
		if e := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='directory_identities'`).Scan(&n); e != nil || n != 0 {
			t.Fatal("partial link schema escaped rollback", e)
		}
		if _, e := db.Exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_hash,ip,user_agent,expires_at,created_at,audience) VALUES('new','upgrade_user','new-token','csrf','127.0.0.1','test',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'login')`); e == nil {
			t.Fatal("old audience constraint changed despite rollback")
		}
	})
}
