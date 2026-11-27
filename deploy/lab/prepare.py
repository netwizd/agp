#!/usr/bin/env python3
"""Explicit, persistent S0/S1 test deployment; not the public release installer.

Run the reviewed script as root on the explicitly authorized disposable lab host.
Preparation never starts public listeners. Activation is a separate command.
"""
import argparse
import base64
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

ETC = Path('/etc/agp-lab')
STATE = Path('/var/lib/agp-lab')
UNITS = Path('/etc/systemd/system')
USERS = {'cp': 'agp-lab-cp', 'journal': 'agp-lab-journal',
         'pgcp': 'agp-lab-pgcp', 'pgjournal': 'agp-lab-pgjournal', 'web': 'agp-lab-web'}


def run(argv, *, user=None, env=None, stdin=None):
    command = (["/usr/sbin/runuser", "-u", user, "--"] if user else []) + [str(x) for x in argv]
    result = subprocess.run(command, input=stdin, text=True, capture_output=True,
                            env=env, check=False, timeout=180)
    if result.returncode:
        # Do not print subprocess input or environment (both may carry secrets).
        raise RuntimeError(f'{Path(str(argv[0])).name} failed (exit {result.returncode}): {result.stderr.strip()[:1800]}')
    return result.stdout


def account(name):
    return pwd.getpwnam(name)


def directory(path, owner='root', mode=0o750, group=None):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError(f'symlink directory rejected: {path}')
    path.mkdir(mode=mode, parents=False, exist_ok=True)
    person = account(owner)
    os.chown(path, person.pw_uid, grp.getgrnam(group).gr_gid if group else person.pw_gid)
    os.chmod(path, mode)


def write(path, content, owner='root', mode=0o600, group=None):
    path = Path(path)
    person = account(owner)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchown(stream.fileno(), person.pw_uid, grp.getgrnam(group).gr_gid if group else person.pw_gid)
        os.fchmod(stream.fileno(), mode)


def document(path, value, **kwargs):
    write(path, json.dumps(value, indent=2) + '\n', **kwargs)


def protected(path, executable=False):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)):
        raise RuntimeError(f'absolute simple path required: {path}')
    for current in [path] + list(path.parents):
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError(f'root-owned non-writable path required: {current}')
    info = path.stat()
    if executable and (not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111):
        raise RuntimeError(f'regular executable required: {path}')
    return path


def host(value):
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value) or len(value) > 253 or '.' not in value or '..' in value:
            raise ValueError('host must be a lower-case DNS name or usable IPv4 address')
        if re.fullmatch(r'[0-9.]+', value):
            raise ValueError('invalid IPv4 address')
        return value
    if parsed.version != 4 or parsed.is_unspecified or parsed.is_multicast:
        raise ValueError('only usable IPv4 addresses are supported by this lab helper')
    return str(parsed)


def san(value):
    try:
        return 'IP:' + str(ipaddress.ip_address(value))
    except ValueError:
        return 'DNS:' + value


def key_public(path):
    run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', path])
    os.chmod(path, 0o600)
    raw = subprocess.check_output(['openssl', 'pkey', '-in', str(path), '-pubout', '-outform', 'DER'])
    if len(raw) != 44 or raw[:12].hex() != '302a300506032b6570032100':
        raise RuntimeError('unexpected Ed25519 SPKI encoding')
    return raw[-32:].hex()


def make_ca(label):
    root = ETC / 'operators' / label
    directory(root, mode=0o700)
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '365',
         '-subj', '/CN=AGP LAB ' + label, '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
         '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', root/'ca.key', '-out', root/'ca.pem'])
    os.chmod(root/'ca.key', 0o600)
    return root


def issue(ca, label, alternative, purpose, destination, owner):
    key, csr, cert, ext = [ca/(label + suffix) for suffix in ('.key', '.csr', '.pem', '.ext')]
    run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN='+label,
         '-keyout', key, '-out', csr])
    write(ext, f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={purpose}\nsubjectAltName={alternative}\n')
    run(['openssl', 'x509', '-req', '-in', csr, '-CA', ca/'ca.pem', '-CAkey', ca/'ca.key',
         '-set_serial', str(secrets.randbits(150) + 1), '-days', '90', '-sha256', '-extfile', ext, '-out', cert])
    write(destination/(label+'.pem'), cert.read_text(), owner)
    write(destination/(label+'.key'), key.read_text(), owner)
    write(destination/(label+'-ca.pem'), (ca/'ca.pem').read_text(), owner)
    os.chmod(key, 0o600)


def environment(path, values, owner):
    # systemd EnvironmentFile syntax, not arbitrary shell source.
    text = ''.join(f'{name}="{value.replace(chr(92), chr(92)*2).replace(chr(34), chr(92)+chr(34))}"\n' for name, value in values.items())
    write(path, text, owner)


def service(description, user, start, extra='', writes=''):
    return f'''[Unit]
Description={description}
After=network.target
{extra}
[Service]
Type=simple
User={user}
Group={user}
ExecStart={start}
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={writes or STATE}
CapabilityBoundingSet=
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
SystemCallArchitectures=native
TimeoutStopSec=90

[Install]
WantedBy=multi-user.target
'''


def nginx_command(config):
    root = Path(config['nginxRuntimeRoot'])
    return [root/'lib/ld-linux-x86-64.so.2', '--library-path', root/'lib', root/'bin/nginx',
            '-e', 'stderr', '-p', str(STATE/'nginx')+'/', '-c', ETC/'nginx.conf']


def prepare(args):
    if ETC.exists() or STATE.exists():
        raise RuntimeError('existing /etc/agp-lab or /var/lib/agp-lab rejected; never overwrite an installation')
    management, login, portal = host(args.management_host), host(args.login_host), host(args.portal_host)
    if len({management, login, portal}) != 3:
        raise RuntimeError('management, login and portal hosts must differ')
    binaries = protected(args.bin_dir)
    pg = protected(args.pg_bindir)
    runtime = protected(args.nginx_runtime_root)
    for name in ['agp', 'agpctl', 'agp-security-journal']:
        protected(binaries/name, True)
    for name in ['initdb', 'postgres', 'psql', 'createdb']:
        protected(pg/name, True)
    protected(runtime/'lib/ld-linux-x86-64.so.2', True)
    protected(runtime/'bin/nginx', True)
    for name in USERS.values():
        try:
            account(name)
        except KeyError:
            run(['useradd', '--system', '--user-group', '--home-dir', '/nonexistent', '--no-create-home', '--shell', '/usr/sbin/nologin', name])
        else:
            raise RuntimeError(f'existing service user rejected: {name}')
    directory(ETC, mode=0o755)
    directory(STATE, mode=0o755)
    directory(ETC/'operators', mode=0o700)
    directory(ETC/'public', mode=0o755)
    for role in ['cp', 'journal']:
        directory(ETC/role, group=USERS[role])
        directory(STATE/role, USERS[role], 0o700)
    directory(ETC/'browser', mode=0o700)
    directory(STATE/'nginx', USERS['web'], 0o750)
    directory(STATE/'cp/downloads', USERS['cp'], 0o700)
    for role in ['cp', 'journal']:
        directory(STATE/('pg'+role), USERS['pg'+role], 0o700)
    browser, journal_ca, central = [make_ca(x) for x in ['browser-ca', 'journal-ca', 'central-auth-ca']]
    issue(browser, 'listener', ','.join([san(management), san(login)]), 'serverAuth', ETC/'browser', 'root')
    # The HTTPS service runs entirely as the web user, including its master.
    # Give it read access to this listener only, never to CA or application keys.
    directory(ETC/'browser', group=USERS['web'])
    for name in ['listener.pem', 'listener.key', 'listener-ca.pem']:
        os.chown(ETC/'browser'/name, 0, grp.getgrnam(USERS['web']).gr_gid)
        os.chmod(ETC/'browser'/name, 0o640)
    write(ETC/'public/browser-ca.pem', (browser/'ca.pem').read_text(), mode=0o644)
    issue(journal_ca, 'journal-server', 'IP:127.0.0.1', 'serverAuth', ETC/'journal', USERS['journal'])
    issue(journal_ca, 'journal-client', 'URI:spiffe://agp/control-plane/lab', 'clientAuth', ETC/'cp', USERS['cp'])
    issue(central, 'central-auth', 'IP:127.0.0.1', 'serverAuth', ETC/'cp', USERS['cp'])
    signing = ETC/'operators/journal-signing.pem'
    public = key_public(signing)
    write(ETC/'journal/signing.pem', signing.read_text(), USERS['journal'])
    # The signer does not receive the independent approval private key.
    approver = key_public(ETC/'operators/restore-approver.pem')
    document(ETC/'journal/config.json', {
        'authorityId': 'agp_lab', 'keyId': 'journal_lab_1', 'signingKeyFile': str(ETC/'journal/signing.pem'),
        'listenAddress': '127.0.0.1:19444', 'tlsCertificateFile': str(ETC/'journal/journal-server.pem'),
        'tlsKeyFile': str(ETC/'journal/journal-server.key'), 'clientCAFile': str(ETC/'journal/journal-server-ca.pem'),
        'readClientURIs': ['spiffe://agp/control-plane/lab'], 'appendClientURIs': ['spiffe://agp/control-plane/lab'],
        'approvalKeys': {'lab_restore_approver_1': {'principalId': 'lab_restore_operator', 'publicKey': approver,
            'allowedKinds': ['advance_authority_epoch', 'unblock_principal', 'enable_resource', 'clear_route_deny']}}
    }, owner='root', group=USERS['journal'], mode=0o640)
    document(ETC/'cp/mfa-keyring.json', {'active': 'lab_mfa_1', 'keys': {'lab_mfa_1': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')}}, owner=USERS['cp'])
    cp = {
        'AGP_DATABASE_DRIVER': 'postgres', 'AGP_DATABASE_DSN': 'host=/run/agp-lab-pgcp dbname=agp_cp user=agp_lab_cp sslmode=disable',
        'AGP_HTTP_ADDR': '127.0.0.1:18080', 'AGP_DOWNLOADS_DIR': str(STATE/'cp/downloads'),
        'AGP_PORTAL_HOST': portal, 'AGP_MANAGEMENT_ORIGIN': 'https://'+management, 'AGP_LOGIN_ORIGIN': 'https://'+login,
        'AGP_SECURE_PROFILE': 'true', 'AGP_CONFIGURATION_ENABLED': 'true', 'AGP_COOKIE_SECURE': 'true',
        'AGP_MFA_KEYRING_FILE': str(ETC/'cp/mfa-keyring.json'), 'AGP_MFA_KEY_FILE': str(ETC/'cp/mfa-keyring.json'),
        'AGP_AUTH_MTLS_ADDR': '127.0.0.1:18444', 'AGP_AUTH_MTLS_CERT_FILE': str(ETC/'cp/central-auth.pem'),
        'AGP_AUTH_MTLS_KEY_FILE': str(ETC/'cp/central-auth.key'), 'AGP_AUTH_MTLS_CLIENT_CA_FILE': str(ETC/'cp/central-auth-ca.pem'),
        'AGP_JOURNAL_URL': 'https://127.0.0.1:19444', 'AGP_JOURNAL_AUTHORITY_ID': 'agp_lab', 'AGP_JOURNAL_KEY_ID': 'journal_lab_1',
        'AGP_JOURNAL_PUBLIC_KEY': public, 'AGP_JOURNAL_CLIENT_CERT': str(ETC/'cp/journal-client.pem'),
        'AGP_JOURNAL_CLIENT_KEY': str(ETC/'cp/journal-client.key'), 'AGP_JOURNAL_CA': str(ETC/'cp/journal-client-ca.pem'),
        'AGP_TRUST_PROXY_HEADERS': 'true', 'AGP_TRUSTED_PROXY_CIDRS': '127.0.0.1/32'
    }
    journal = {'AGP_JOURNAL_DATABASE_DSN': 'host=/run/agp-lab-pgjournal dbname=agp_journal user=agp_lab_journal sslmode=disable'}
    environment(ETC/'cp/cp.env', cp, 'root')
    environment(ETC/'journal/journal.env', journal, 'root')
    password = secrets.token_urlsafe(24)
    write(ETC/'operators/bootstrap-admin.password', password+'\n')
    config = {'managementHost': management, 'loginHost': login, 'portalHost': portal, 'binDir': str(binaries),
              'pgBindir': str(pg), 'nginxRuntimeRoot': str(runtime), 'adminUsername': args.admin_username,
              'cpEnvironment': cp, 'journalEnvironment': journal}
    document(ETC/'deployment.json', config)
    for role in ['cp', 'journal']:
        pguser = USERS['pg'+role]
        data = STATE/('pg'+role)
        unit = service('AGP lab independent PostgreSQL '+role, pguser,
                       f'{pg}/postgres -D {data}', writes=f'{data} /run/agp-lab-pg{role}')
        unit = unit.replace('Restart=on-failure', f'RuntimeDirectory=agp-lab-pg{role}\nRuntimeDirectoryMode=0755\nKillSignal=SIGINT\nRestart=on-failure')
        write(UNITS/f'agp-lab-pg{role}.service', unit, mode=0o644)
    journal_unit = service('AGP lab independent security journal', USERS['journal'],
                           f'{binaries}/agp-security-journal serve -config {ETC}/journal/config.json',
                           extra='Requires=agp-lab-pgjournal.service\nAfter=agp-lab-pgjournal.service', writes=str(STATE/'journal'))
    journal_unit = journal_unit.replace('Type=simple', f'Type=simple\nEnvironmentFile={ETC}/journal/journal.env')
    write(UNITS/'agp-lab-journal.service', journal_unit, mode=0o644)
    cp_unit = service('AGP lab secure current control plane', USERS['cp'], str(binaries/'agp'),
                      extra='Requires=agp-lab-pgcp.service agp-lab-journal.service\nAfter=agp-lab-pgcp.service agp-lab-journal.service', writes=str(STATE/'cp'))
    cp_unit = cp_unit.replace('Type=simple', f'Type=simple\nEnvironmentFile={ETC}/cp/cp.env')
    write(UNITS/'agp-lab-cp.service', cp_unit, mode=0o644)
    listen = f'''listen 443 ssl; http2 on;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_certificate {ETC}/browser/listener.pem;
        ssl_certificate_key {ETC}/browser/listener.key;'''
    proxy = '''proxy_pass http://127.0.0.1:18080;
          proxy_http_version 1.1;
          proxy_set_header Host $http_host;
          proxy_set_header X-Forwarded-Host $http_host;
          proxy_set_header X-Forwarded-Proto https;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $remote_addr;'''
    nginx = f'''worker_processes auto;
pid /run/agp-lab-frontdoor/nginx.pid;
error_log stderr;
events {{ worker_connections 1024; }}
http {{
  access_log {STATE}/nginx/access.log;
  client_body_temp_path body; proxy_temp_path proxy; fastcgi_temp_path fastcgi;
  uwsgi_temp_path uwsgi; scgi_temp_path scgi;
  client_max_body_size 20m;
  server {{ listen 80 default_server; server_name _; return 308 https://{management}$request_uri; }}
  server {{ {listen} server_name {management} {login};
    location = / {{ return 302 /config-ui/; }}
    location / {{ {proxy} }}
  }}
}}
'''
    write(ETC/'nginx.conf', nginx, mode=0o640, group=USERS['web'])
    command = ' '.join(str(x) for x in nginx_command(config))
    front = service('AGP lab HTTPS front door', USERS['web'], command+' -g "daemon off;"',
                    extra='Requires=agp-lab-cp.service\nAfter=agp-lab-cp.service', writes=f'{STATE}/nginx /run/agp-lab-frontdoor')
    front = front.replace('Type=simple', 'Type=simple\nRuntimeDirectory=agp-lab-frontdoor\nRuntimeDirectoryMode=0755')
    front = front.replace('ExecStart=', 'ExecStartPre='+command+' -t\nExecStart=', 1)
    front = front.replace('CapabilityBoundingSet=', 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE')
    front = front.replace('Restart=on-failure', 'ExecReload=/bin/kill -s HUP $MAINPID\nRestart=on-failure')
    write(UNITS/'agp-lab-frontdoor.service', front, mode=0o644)
    write(ETC/'operators/prepared', 'prepared\n')
    print('Prepared persistent secure S0/S1 lab. Public listeners remain stopped.')
    print('Review /etc/agp-lab and agp-lab-*.service, then run: prepare.py activate')


def stage(name, action):
    marker = ETC/'operators'/('stage-'+name)
    if not marker.exists():
        action()
        write(marker, 'completed\n')


def activate():
    protected(ETC/'deployment.json')
    if not (ETC/'operators/prepared').is_file():
        raise RuntimeError('preparation was not completed; do not activate a partial configuration')
    config = json.loads((ETC/'deployment.json').read_text())
    pg, binaries = Path(config['pgBindir']), Path(config['binDir'])
    envbase = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
    cp_env = envbase | config['cpEnvironment']
    journal_env = envbase | config['journalEnvironment']
    run(['systemctl', 'daemon-reload'])
    for role in ['cp', 'journal']:
        def initialize(role=role):
            user, data = USERS['pg'+role], STATE/('pg'+role)
            admin, app = 'agp_lab_'+role+'_admin', 'agp_lab_'+role
            if (data/'PG_VERSION').exists():
                raise RuntimeError('partial PostgreSQL initialization requires review; data is never reset')
            run([pg/'initdb', '-D', data, '-U', admin, '--auth-local=peer', '--auth-host=reject', '--encoding=UTF8', '--locale=C.UTF-8'], user=user, env=envbase)
            with (data/'postgresql.conf').open('a') as stream:
                stream.write(f"\nlisten_addresses = ''\nunix_socket_directories = '/run/agp-lab-pg{role}'\nunix_socket_permissions = 0777\nmax_connections = 30\nshared_buffers = '128MB'\n")
            (data/'pg_hba.conf').write_text('local all all peer map=agp_lab\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n')
            (data/'pg_ident.conf').write_text(f'agp_lab {user} {admin}\nagp_lab {USERS[role]} {app}\n')
            for name in ['pg_hba.conf', 'pg_ident.conf']:
                person = account(user)
                os.chown(data/name, person.pw_uid, person.pw_gid)
                os.chmod(data/name, 0o600)
        stage('initdb-'+role, initialize)
        run(['systemctl', 'start', f'agp-lab-pg{role}.service'])
        def database(role=role):
            user, admin, app = USERS['pg'+role], 'agp_lab_'+role+'_admin', 'agp_lab_'+role
            dsn = f'host=/run/agp-lab-pg{role} user={admin} dbname=postgres'
            deadline = time.monotonic()+30
            while True:
                try:
                    run([pg/'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-d', dsn, '-c', 'SELECT 1'], user=user, env=envbase)
                    break
                except RuntimeError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(.3)
            run([pg/'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-d', dsn, '-c', f'CREATE ROLE {app} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;'], user=user, env=envbase)
            run([pg/'createdb', '--maintenance-db='+dsn, '--owner='+app, 'agp_'+role], user=user, env=envbase)
        stage('database-'+role, database)
    def migrate():
        run([binaries/'agp-security-journal', 'migrate', '-config', ETC/'journal/config.json'], user=USERS['journal'], env=journal_env)
        run([binaries/'agp-security-journal', 'verify', '-config', ETC/'journal/config.json'], user=USERS['journal'], env=journal_env)
    stage('journal-migration', migrate)
    run(['systemctl', 'start', 'agp-lab-journal.service'])
    # mTLS verifies journal readiness through the same real client used by CP.
    for attempt in range(40):
        try:
            run([binaries/'agpctl', 'identity-profile', '--preview'], user=USERS['cp'], env=cp_env)
            break
        except RuntimeError:
            if attempt == 39:
                raise
            time.sleep(.3)
    bootstrap_env = cp_env | {'AGP_SECURE_PROFILE': 'false', 'AGP_CONFIGURATION_ENABLED': 'false'}
    def administrator():
        result = run([binaries/'agpctl', 'create-admin', '-username', config['adminUsername']], user=USERS['cp'], env=bootstrap_env,
                     stdin=(ETC/'operators/bootstrap-admin.password').read_text())
        match = re.search(r'created admin user [^\n]+ \(([A-Za-z0-9_-]+)\)', result)
        if not match:
            raise RuntimeError('bootstrap administrator ID was not returned')
        write(ETC/'operators/bootstrap-admin.id', match[1]+'\n')
    stage('administrator', administrator)
    def access():
        manifest = ETC/'cp/configuration-bootstrap.json'
        document(manifest, {'grants': [{'principalId': (ETC/'operators/bootstrap-admin.id').read_text().strip(),
                    'permission': 'config.approve', 'scopeType': 'global', 'scopeId': ''}], 'ownership': []}, owner=USERS['cp'])
        run([binaries/'agpctl', 'configuration-access', '--bootstrap-manifest', manifest], user=USERS['cp'], env=bootstrap_env)
    stage('configuration-access', access)
    stage('identity-activation', lambda: run([binaries/'agpctl', 'identity-profile', '--activate', '--revoke-sessions'], user=USERS['cp'], env=cp_env))
    run(['systemctl', 'start', 'agp-lab-cp.service'])
    for attempt in range(60):
        try:
            with urllib.request.urlopen('http://127.0.0.1:18080/readyz', timeout=2) as response:
                if response.status == 200:
                    break
        except (OSError, urllib.error.URLError):
            pass
        if attempt == 59:
            raise RuntimeError('control-plane readiness did not pass; front door remains stopped')
        time.sleep(.5)
    directory(Path('/run/agp-lab-frontdoor'), USERS['web'], mode=0o755)
    # ExecStartPre checks Nginx with the unit's web UID and bind capability.
    run(['systemctl', 'start', 'agp-lab-frontdoor.service'])
    units = [f'agp-lab-{name}.service' for name in ['pgcp', 'pgjournal', 'journal', 'cp', 'frontdoor']]
    try:
        # is-active with several names succeeds if *any* name is active.
        for unit in units:
            run(['systemctl', 'is-active', '--quiet', unit])
        browser = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cafile=str(ETC/'public/browser-ca.pem'))))
        origin = 'https://'+config['managementHost']
        for attempt in range(20):
            try:
                with browser.open(origin+'/auth/v2/bootstrap', timeout=3) as response:
                    if response.status != 200 or 'application/json' not in response.headers.get('Content-Type', ''):
                        raise RuntimeError('HTTPS authentication bootstrap smoke failed')
                break
            except urllib.error.HTTPError:
                raise
            except (OSError, urllib.error.URLError):
                if attempt == 19:
                    raise
                time.sleep(.25)
        try:
            browser.open(origin+'/api/v1/admin/users', timeout=5).close()
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise RuntimeError('unauthenticated management API did not reject access with 401') from error
        else:
            raise RuntimeError('unauthenticated management API unexpectedly accepted access')
    except Exception:
        run(['systemctl', 'stop', 'agp-lab-frontdoor.service'])
        raise
    run(['systemctl', 'enable'] + units)
    print('Activated persistent secure S0/S1 lab: https://'+config['managementHost']+'/config-ui/')
    print('Password: root-only /etc/agp-lab/operators/bootstrap-admin.password; mandatory TOTP enrollment at first login.')
    print('Browser CA: /etc/agp-lab/public/browser-ca.pem (private test CA, not a public certificate).')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('prepare')
    create.add_argument('--management-host', required=True)
    create.add_argument('--login-host', required=True)
    create.add_argument('--portal-host', default='portal.agp.test')
    create.add_argument('--admin-username', default='admin')
    create.add_argument('--bin-dir', required=True)
    create.add_argument('--pg-bindir', required=True)
    create.add_argument('--nginx-runtime-root', required=True)
    commands.add_parser('activate')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root is required; this script changes only the explicitly authorized lab installation')
    os.umask(0o077)
    if args.command == 'prepare':
        if not re.fullmatch(r'[a-z][a-z0-9_.-]{2,63}', args.admin_username):
            parser.error('invalid administrator username')
        prepare(args)
    else:
        activate()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print('AGP lab: '+str(error), file=sys.stderr)
        sys.exit(1)
