// Documentation reference DDL checks in two isolated PGlite PostgreSQL engines.
// Usage: node docs/v2/check-reference-db.mjs /tmp/agp-doc-pg/node_modules/@electric-sql/pglite/dist/index.js
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const base = path.dirname(fileURLToPath(import.meta.url));
if (!process.argv[2]) throw new Error('Pass the absolute path to the separately installed PGlite module; no database/network address is accepted.');
const { PGlite } = await import(pathToFileURL(path.resolve(process.argv[2])).href);
let checks = 0;
async function reject(db, sql, expectedCode) {
  try { await db.exec(sql); }
  catch (err) {
    if (expectedCode && err.code !== expectedCode) throw err;
    checks++;
    return;
  }
  throw new Error(`Expected rejection: ${sql}`);
}
const db = new PGlite();
const journal = new PGlite();
try {
  await db.exec(await fs.readFile(path.join(base, 'database.sql'), 'utf8'));
  await journal.exec(await fs.readFile(path.join(base, 'security-journal.sql'), 'utf8'));
  const version = (await db.query('select version()')).rows[0].version;
  console.log(version);
  await db.exec("SELECT 'usr_AbCd-_1'::agp_v2.object_id, '9223372036854775807'::agp_v2.uint63"); checks++;
  await reject(db, "SELECT '../escape'::agp_v2.object_id", '23514');
  await reject(db, 'SELECT (-1)::agp_v2.uint63', '23514');
  await reject(db, "SELECT '9223372036854775808'::agp_v2.uint63", '22003');
  await reject(db, "SELECT 'sha256:bad'::agp_v2.digest", '23514');
  await reject(db, 'SELECT 86401::agp_v2.short_seconds', '23514');
  await db.exec("INSERT INTO agp_v2.principals(id,kind,username,username_key,state) VALUES ('usr_AbC','local','Admin','admin','active')"); checks++;
  await reject(db, "INSERT INTO agp_v2.principals(id,kind,username,username_key,state) VALUES ('usr_other','local','ADMIN','admin','active')", '23505');
  await reject(db, "INSERT INTO agp_v2.principals(id,kind,username,username_key,state,is_break_glass) VALUES ('usr_bad','oidc','bg','bg','active',true)", '23514');
  await reject(db, "INSERT INTO agp_v2.nodes(id,site_id,name,ownership,state,operating_system,architecture) VALUES ('node_bad','site_missing','bad','managed','pending','ubuntu','amd64')", '23503');
  // Disposable non-secret fixtures for AD links and one-time email flow boundaries.
  await db.exec("INSERT INTO agp_v2.principals(id,kind,username,username_key,state) VALUES ('usr_ad','directory','employee','ad:corp:guid','active')"); checks++;
  await db.exec("INSERT INTO agp_v2.directory_providers(id,name,forest_guid,security_guard_id) VALUES ('dir_corp','Corporate','00000000-0000-0000-0000-000000000001','guard_corp')");
  await db.exec("INSERT INTO agp_v2.secret_versions(id,secret_id,version,kind,cipher_object_key,cipher_digest,wrapped_dek,kek_key_id,encryption_suite,created_by) VALUES ('sec_test','secret_test',1,'directory_bind','fixtures/non-secret', 'sha256:' || repeat('a',64),decode(repeat('00',32),'hex'),'test-key','aead-envelope-v1','usr_AbC')");
  const directoryConfig = JSON.parse(await fs.readFile(path.join(base, 'examples/directory-provider.json'), 'utf8'));
  await db.query("INSERT INTO agp_v2.directory_provider_versions(id,provider_id,security_guard_version,content_digest,bind_secret_version_id,ca_secret_version_id,config_json,created_by) VALUES ('dirver_1','dir_corp',1,'sha256:' || repeat('b',64),'sec_test','sec_test',$1::jsonb,'usr_AbC')", [JSON.stringify(directoryConfig)]); checks++;
  await reject(db, "UPDATE agp_v2.directory_provider_versions SET security_guard_version=2 WHERE id='dirver_1'");
  await db.exec("INSERT INTO agp_v2.directory_identities(id,provider_id,forest_guid,object_guid,principal_id,authenticator_version) VALUES ('ad_link','dir_corp','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','usr_ad',1)"); checks++;
  await reject(db, "INSERT INTO agp_v2.directory_identities(id,provider_id,forest_guid,object_guid,principal_id,authenticator_version) VALUES ('bad_forest','dir_corp','00000000-0000-0000-0000-000000000099','00000000-0000-0000-0000-000000000003','usr_AbC',1)", '23503');
  await db.exec("INSERT INTO agp_v2.directory_providers(id,name,forest_guid,security_guard_id) VALUES ('dir_other','Other','00000000-0000-0000-0000-000000000001','guard_other')");
  await reject(db, "UPDATE agp_v2.directory_providers SET current_version_id='dirver_1' WHERE id='dir_other'", '23503');
  await db.exec("INSERT INTO agp_v2.identity_contacts(id,principal_id,authenticator_version,address_secret_version_id) VALUES ('contact_1','usr_AbC',1,'sec_test')");
  await db.exec("INSERT INTO agp_v2.identity_flows(id,principal_id,purpose,audience,state,binding_hash,issued_authority_epoch,principal_security_version,expires_at) VALUES ('flow_1','usr_AbC','verify_email','setup','pending_primary','sha256:' || repeat('c',64),1,0,now()+interval '5 minutes')"); checks++;
  await reject(db, "UPDATE agp_v2.identity_flows SET expires_at=created_at+interval '6 minutes' WHERE id='flow_1'", '23514');
  await reject(db, "UPDATE agp_v2.identity_flows SET failed_attempts=6 WHERE id='flow_1'", '23514');
  await reject(db, "UPDATE agp_v2.identity_flows SET state='completed' WHERE id='flow_1'", '23514');
  await db.exec("INSERT INTO agp_v2.email_challenges(id,flow_id,contact_id,contact_authenticator_version,purpose,audience,issued_authority_epoch,generation,code_mac,mac_key_id,delivery_state,expires_at) VALUES ('challenge_1','flow_1','contact_1',1,'verify_email','setup',1,1,decode(repeat('00',32),'hex'),'external-pepper-test','queued',now()+interval '5 minutes')"); checks++;
  await reject(db, "UPDATE agp_v2.email_challenges SET code_mac=decode(repeat('00',31),'hex') WHERE id='challenge_1'", '23514');
  await reject(db, "INSERT INTO agp_v2.email_challenges(id,flow_id,contact_id,contact_authenticator_version,purpose,audience,issued_authority_epoch,generation,code_mac,mac_key_id,delivery_state,expires_at) VALUES ('challenge_2','flow_1','contact_1',1,'verify_email','setup',1,2,decode(repeat('00',32),'hex'),'external-pepper-test','queued',now()+interval '5 minutes')", '23505');
  await db.exec("UPDATE agp_v2.email_challenges SET consumed_at=now() WHERE id='challenge_1'");
  await reject(db, "UPDATE agp_v2.email_challenges SET revoked_at=now() WHERE id='challenge_1'", '23514');
  // A report targets exactly one immutable config/WAF/profile/zone revision.
  await db.exec("INSERT INTO agp_v2.sites(id,name) VALUES ('site_validation','Validation fixture')");
  await db.exec("INSERT INTO agp_v2.config_revisions(id,revision_number,schema_version,capacity_profile,canonical_size_bytes,content_digest,canonical_json,state,created_by) VALUES ('cfg_validation',1,'agp.config/v1alpha1','pilot-500',2,'sha256:' || repeat('a',64),'{}','draft','usr_AbC')");
  await db.exec("INSERT INTO agp_v2.policy_profiles(id,name) VALUES ('profile_validation','Validation fixture')");
  await db.exec("INSERT INTO agp_v2.policy_profile_versions(id,profile_id,version,content_digest,level,state,created_by) VALUES ('profilever_validation','profile_validation',1,'sha256:' || repeat('b',64),'global','draft','usr_AbC')");
  await db.exec("INSERT INTO agp_v2.waf_policy_revisions(id,policy_id,site_id,name,revision_number,content_digest,canonical_json,engine,ruleset_version_id,paranoia_level,inbound_anomaly_threshold,outbound_anomaly_threshold,state,created_by) VALUES ('waf_validation','policy_validation','site_validation','Validation fixture',1,'sha256:' || repeat('c',64),'{}','modsecurity','ruleset_fixture',1,5,4,'draft','usr_AbC')");
  await db.exec("INSERT INTO agp_v2.waf_zones(id,site_id,created_by) VALUES ('zone_validation','site_validation','usr_AbC')");
  await db.exec("INSERT INTO agp_v2.waf_zone_revisions(id,zone_id,site_id,revision_number,name,owner_id,policy_revision_id,mode,membership_kind,reason,canonical_json,content_digest,state,created_by) VALUES ('zonerev_validation','zone_validation','site_validation',1,'Validation fixture','usr_AbC','waf_validation','detection','explicit','Non-secret fixture','{}','sha256:' || repeat('d',64),'draft','usr_AbC')");
  const reportTargets = [['revision_id', 'cfg_validation'], ['waf_revision_id', 'waf_validation'], ['profile_version_id', 'profilever_validation'], ['zone_revision_id', 'zonerev_validation']];
  for (const [column, id] of reportTargets) {
    await db.exec(`INSERT INTO agp_v2.validation_reports(id,${column},content_digest,validator_version,outcome,findings_json) VALUES ('validation_${column}','${id}','sha256:' || repeat('e',64),'fixture','failed','[]')`); checks++;
  }
  await reject(db, "INSERT INTO agp_v2.validation_reports(id,content_digest,validator_version,outcome,findings_json) VALUES ('validation_none','sha256:' || repeat('e',64),'fixture','failed','[]')", '23514');
  await reject(db, "INSERT INTO agp_v2.validation_reports(id,revision_id,zone_revision_id,content_digest,validator_version,outcome,findings_json) VALUES ('validation_multiple','cfg_validation','zonerev_validation','sha256:' || repeat('e',64),'fixture','failed','[]')", '23514');
  await reject(db, "INSERT INTO agp_v2.validation_reports(id,waf_revision_id,profile_version_id,content_digest,validator_version,outcome,findings_json) VALUES ('validation_multiple_policy','waf_validation','profilever_validation','sha256:' || repeat('e',64),'fixture','failed','[]')", '23514');
  await reject(db, "INSERT INTO agp_v2.validation_reports(id,zone_revision_id,content_digest,validator_version,outcome,findings_json) VALUES ('validation_missing_zone','zone_missing','sha256:' || repeat('e',64),'fixture','failed','[]')", '23503');
  await journal.exec("INSERT INTO agp_security_journal.authorities(id,authority_epoch) VALUES ('auth_main',1)"); checks++;
  await reject(journal, "UPDATE agp_security_journal.authorities SET authority_epoch=0,row_version=1 WHERE id='auth_main'");
  await journal.exec("UPDATE agp_security_journal.authorities SET authority_epoch=2,row_version=1 WHERE id='auth_main'"); checks++;
  await reject(journal, "UPDATE agp_security_journal.authorities SET authority_epoch=1,row_version=2 WHERE id='auth_main'");
  const tables = (await db.query("SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema='agp_v2' AND table_type='BASE TABLE'")).rows[0].n;
  const journalTables = (await journal.query("SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema='agp_security_journal' AND table_type='BASE TABLE'")).rows[0].n;
  console.log(`PASS: CP=${tables} tables, journal=${journalTables} tables in separate engines; ${checks} boundary/constraint assertions.`);
  console.log('This does not qualify native PostgreSQL 17, runtime migrations, permissions, filesystem durability, HA or security journal service logic.');
} finally {
  await db.close();
  await journal.close();
}
