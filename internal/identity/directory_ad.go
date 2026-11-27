package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
)

// DirectorySecrets are resolved only from installation-controlled immutable
// version references. Resolve transfers a fresh password buffer to the caller,
// which clears it after use; resolvers must never reuse or retain that buffer.
type DirectorySecrets struct {
	BindPassword      []byte
	CACertificatesPEM []byte
}
type DirectorySecretResolver interface {
	ResolveDirectorySecrets(context.Context, string, string) (DirectorySecrets, error)
}
type DirectoryAccount struct {
	ForestGUID, ObjectGUID, DN, UPN, DisplayName string
	GroupObjectGUIDs, AccessGroupIDs             []string
}

// ADConnector uses one TLS-qualified DC for an operation, independent short
// user-bind connections, referrals disabled and a fresh read for every allow.
// Network prefixes are trusted installation policy, never provider/caller data.
type ADConnector struct {
	secrets  DirectorySecretResolver
	prefixes []netip.Prefix
	lookup   func(context.Context, string) ([]netip.Addr, error)
	dial     func(context.Context, string, string) (net.Conn, error)
	slots    chan struct{}
}

func NewADConnector(secrets DirectorySecretResolver, prefixes []netip.Prefix) (*ADConnector, error) {
	if secrets == nil || len(prefixes) == 0 || len(prefixes) > 64 {
		return nil, ErrDirectoryInvalid
	}
	c := &ADConnector{secrets: secrets, prefixes: append([]netip.Prefix{}, prefixes...), slots: make(chan struct{}, 4)}
	for _, p := range c.prefixes {
		if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() {
			return nil, ErrDirectoryInvalid
		}
	}
	c.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	c.dial = (&net.Dialer{KeepAlive: -1}).DialContext
	return c, nil
}

type adOperation struct {
	ctx       context.Context
	cancel    context.CancelFunc
	secrets   DirectorySecrets
	config    DirectoryProviderDocument
	connector *ADConnector
	budget    *atomic.Int64
}

func (c *ADConnector) operation(ctx context.Context, in DirectoryProviderDocument) (*adOperation, error) {
	d, e := directoryDocument(in)
	if e != nil {
		return nil, e
	}
	operation, cancel := context.WithTimeout(ctx, time.Duration(d.Configuration.Spec.OperationTimeoutSeconds)*time.Second)
	select {
	case c.slots <- struct{}{}:
	case <-operation.Done():
		cancel()
		return nil, ErrDirectoryUnavailable
	}
	fail := func() (*adOperation, error) { <-c.slots; cancel(); return nil, ErrDirectoryUnavailable }
	secrets, e := c.secrets.ResolveDirectorySecrets(operation, d.Configuration.Spec.BindSecretVersionID, d.Configuration.Spec.CASecretVersionID)
	secrets.CACertificatesPEM = append([]byte{}, secrets.CACertificatesPEM...)
	if e != nil || len(secrets.BindPassword) == 0 || len(secrets.BindPassword) > 65536 || len(secrets.CACertificatesPEM) == 0 || len(secrets.CACertificatesPEM) > 262144 {
		for i := range secrets.BindPassword {
			secrets.BindPassword[i] = 0
		}
		return fail()
	}
	for _, dn := range append(append([]string{d.Configuration.Spec.BindDN}, d.Configuration.Spec.UserBaseDNs...), d.Configuration.Spec.GroupBaseDNs...) {
		if _, e = ldap.ParseDN(dn); e != nil {
			for i := range secrets.BindPassword {
				secrets.BindPassword[i] = 0
			}
			return fail()
		}
	}
	budget := &atomic.Int64{}
	budget.Store(16 << 20)
	return &adOperation{ctx: operation, cancel: cancel, secrets: secrets, config: d.Configuration, connector: c, budget: budget}, nil
}
func (o *adOperation) close() {
	for i := range o.secrets.BindPassword {
		o.secrets.BindPassword[i] = 0
	}
	o.cancel()
	<-o.connector.slots
}

type adConnection struct {
	ldap     *ldap.Conn
	raw      net.Conn
	stop     func() bool
	endpoint DirectoryEndpoint
	ip       netip.Addr
	tls      *tls.Config
}

func (c *adConnection) close() { c.stop(); _ = c.raw.Close(); _ = c.ldap.Close() }
func (c *ADConnector) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, p := range c.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
func (o *adOperation) connect() (out *adConnection, err error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(o.secrets.CACertificatesPEM) {
		return nil, ErrDirectoryUnavailable
	}
	for _, endpoint := range o.config.Spec.Endpoints {
		ips, e := o.connector.lookup(o.ctx, endpoint.Host)
		if e != nil || len(ips) == 0 || len(ips) > 32 {
			continue
		}
		permitted := true
		for _, ip := range ips {
			if !o.connector.allowed(ip) {
				permitted = false
				break
			}
		}
		if !permitted {
			continue
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: endpoint.Host}
		for _, ip := range ips {
			connection, e := o.dial(endpoint, ip.Unmap(), cfg)
			if e == nil {
				return connection, nil
			}
			if o.ctx.Err() != nil {
				return nil, ErrDirectoryUnavailable
			}
		}
	}
	return nil, ErrDirectoryUnavailable
}
func (o *adOperation) dial(endpoint DirectoryEndpoint, ip netip.Addr, cfg *tls.Config) (*adConnection, error) {
	raw, e := o.connector.dial(o.ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(endpoint.Port)))
	if e != nil {
		return nil, ErrDirectoryUnavailable
	}
	raw = &directoryReadBudget{Conn: raw, remaining: o.budget}
	stop := context.AfterFunc(o.ctx, func() { _ = raw.Close() })
	deadline, _ := o.ctx.Deadline()
	if e = raw.SetDeadline(deadline); e != nil {
		stop()
		_ = raw.Close()
		return nil, ErrDirectoryUnavailable
	}
	fail := func() (*adConnection, error) { stop(); _ = raw.Close(); return nil, ErrDirectoryUnavailable }
	var l *ldap.Conn
	if o.config.Spec.Transport == "ldaps" {
		secure := tls.Client(raw, cfg.Clone())
		if e = secure.HandshakeContext(o.ctx); e != nil {
			return fail()
		}
		l = ldap.NewConn(secure, true)
		l.SetTimeout(time.Until(deadline))
		l.Start()
	} else {
		l = ldap.NewConn(raw, false)
		l.SetTimeout(time.Until(deadline))
		l.Start()
		if e = l.StartTLS(cfg.Clone()); e != nil {
			_ = l.Close()
			return fail()
		}
		state, ok := l.TLSConnectionState()
		if !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
			_ = l.Close()
			return fail()
		}
	}
	return &adConnection{ldap: l, raw: raw, stop: stop, endpoint: endpoint, ip: ip, tls: cfg}, nil
}
func (o *adOperation) service() (out *adConnection, domainDN string, err error) {
	c, e := o.connect()
	if e != nil {
		return nil, "", e
	}
	// Once bind begins there is no endpoint retry, including an unknown outcome.
	if e = c.ldap.Bind(o.config.Spec.BindDN, string(o.secrets.BindPassword)); e != nil {
		c.close()
		return nil, "", ErrDirectoryUnavailable
	}
	domainDN, e = o.forest(c)
	if e != nil {
		c.close()
		return nil, "", e
	}
	return c, domainDN, nil
}
func (o *adOperation) search(c *adConnection, base string, scope, limit int, filter string, attrs []string) ([]*ldap.Entry, error) {
	if o.ctx.Err() != nil {
		return nil, ErrDirectoryUnavailable
	}
	result, e := c.ldap.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, limit, o.config.Spec.OperationTimeoutSeconds, false, filter, attrs, nil))
	if e != nil || result == nil || len(result.Referrals) > 0 || len(result.Entries) > limit {
		return nil, ErrDirectoryUnavailable
	}
	return result.Entries, nil
}
func adAttribute(e *ldap.Entry, name string) ([]byte, error) {
	var out []byte
	found := false
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			if found || len(a.ByteValues) != 1 {
				return nil, ErrDirectoryUnavailable
			}
			out = a.ByteValues[0]
			found = true
		}
	}
	if !found || len(out) == 0 {
		return nil, ErrDirectoryUnavailable
	}
	return out, nil
}
func adText(e *ldap.Entry, name string) (string, error) {
	v, err := adAttribute(e, name)
	if err != nil || !utf8.Valid(v) || len(v) > 4096 || strings.ContainsRune(string(v), 0) {
		return "", ErrDirectoryUnavailable
	}
	return string(v), nil
}
func (o *adOperation) forest(c *adConnection) (string, error) {
	entries, e := o.search(c, "", ldap.ScopeBaseObject, 1, "(objectClass=*)", []string{"defaultNamingContext", "configurationNamingContext", "supportedCapabilities", "isGlobalCatalogReady"})
	if e != nil || len(entries) != 1 {
		return "", ErrDirectoryUnavailable
	}
	root := entries[0]
	caps := root.GetEqualFoldAttributeValues("supportedCapabilities")
	activeDirectory := false
	for _, cap := range caps {
		if cap == "1.2.840.113556.1.4.800" {
			activeDirectory = true
		}
	}
	if !activeDirectory || !strings.EqualFold(root.GetEqualFoldAttributeValue("isGlobalCatalogReady"), "TRUE") {
		return "", ErrDirectoryUnavailable
	}
	domain, e := adText(root, "defaultNamingContext")
	if e != nil {
		return "", e
	}
	config, e := adText(root, "configurationNamingContext")
	if e != nil {
		return "", e
	}
	expected, err := ldap.ParseDN("DC=" + strings.ReplaceAll(o.config.Spec.DomainDNS, ".", ",DC="))
	actual, err2 := ldap.ParseDN(domain)
	if err != nil || err2 != nil || !expected.EqualFold(actual) {
		return "", ErrDirectoryUnavailable
	}
	for _, base := range append(append([]string{}, o.config.Spec.UserBaseDNs...), o.config.Spec.GroupBaseDNs...) {
		dn, e := ldap.ParseDN(base)
		if e != nil || (!actual.EqualFold(dn) && !actual.AncestorOfFold(dn)) {
			return "", ErrDirectoryUnavailable
		}
	}
	entries, e = o.search(c, config, ldap.ScopeBaseObject, 1, "(objectClass=*)", []string{"objectGUID"})
	if e != nil || len(entries) != 1 {
		return "", ErrDirectoryUnavailable
	}
	guid, e := adAttribute(entries[0], "objectGUID")
	if e != nil {
		return "", e
	}
	decoded, e := ADGUID(guid)
	if e != nil || decoded != o.config.Spec.ForestGUID {
		return "", ErrDirectoryUnavailable
	}
	return domain, nil
}

// ADGUID converts the AD binary objectGUID field order to canonical UUID.
func ADGUID(b []byte) (string, error) {
	if len(b) != 16 {
		return "", ErrDirectoryUnavailable
	}
	zero := true
	for _, v := range b {
		zero = zero && v == 0
	}
	if zero {
		return "", ErrDirectoryUnavailable
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", binary.LittleEndian.Uint32(b[:4]), binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8]), b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]), nil
}
func adBinaryGUID(s string) ([]byte, error) {
	if !directoryUUID.MatchString(s) {
		return nil, ErrDirectoryInvalid
	}
	var b [16]byte
	var a uint32
	var b1, b2 uint16
	var tail [8]byte
	n, e := fmt.Sscanf(s, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", &a, &b1, &b2, &tail[0], &tail[1], &tail[2], &tail[3], &tail[4], &tail[5], &tail[6], &tail[7])
	if e != nil || n != 11 {
		return nil, ErrDirectoryInvalid
	}
	binary.LittleEndian.PutUint32(b[:4], a)
	binary.LittleEndian.PutUint16(b[4:6], b1)
	binary.LittleEndian.PutUint16(b[6:8], b2)
	copy(b[8:], tail[:])
	return b[:], nil
}
func adBinaryFilter(b []byte) string {
	var s strings.Builder
	for _, v := range b {
		fmt.Fprintf(&s, "\\%02x", v)
	}
	return s.String()
}

var adAccountAttrs = []string{"objectGUID", "userPrincipalName", "displayName", "userAccountControl", "msDS-User-Account-Control-Computed", "accountExpires", "tokenGroups"}

func (o *adOperation) account(c *adConnection, filter string) (*ldap.Entry, error) {
	entries := map[string]*ldap.Entry{}
	for _, base := range o.config.Spec.UserBaseDNs {
		result, e := o.search(c, base, ldap.ScopeWholeSubtree, 2, filter, []string{"objectGUID"})
		if e != nil {
			return nil, e
		}
		for _, entry := range result {
			raw, e := adAttribute(entry, "objectGUID")
			if e != nil {
				return nil, e
			}
			id, e := ADGUID(raw)
			if e != nil {
				return nil, e
			}
			if prior := entries[id]; prior != nil && !strings.EqualFold(prior.DN, entry.DN) {
				return nil, ErrDirectoryUnavailable
			}
			entries[id] = entry
		}
		if len(entries) > 1 {
			return nil, ErrProof
		}
	}
	if len(entries) != 1 {
		return nil, ErrProof
	}
	for id, entry := range entries {
		raw, e := adAttribute(entry, "objectGUID")
		if e != nil {
			return nil, e
		}
		exact, e := o.search(c, entry.DN, ldap.ScopeBaseObject, 1, "(&(objectCategory=person)(objectClass=user)(objectGUID="+adBinaryFilter(raw)+"))", adAccountAttrs)
		if e != nil {
			return nil, e
		}
		if len(exact) != 1 {
			return nil, ErrProof
		}
		observed, e := adAttribute(exact[0], "objectGUID")
		if e != nil {
			return nil, e
		}
		actual, e := ADGUID(observed)
		if e != nil {
			return nil, e
		}
		if actual != id {
			return nil, ErrProof
		}
		return exact[0], nil
	}
	return nil, ErrProof
}
func adAccountActive(entry *ldap.Entry, now time.Time) error {
	uacText, e := adText(entry, "userAccountControl")
	if e != nil {
		return e
	}
	computedText, e := adText(entry, "msDS-User-Account-Control-Computed")
	if e != nil {
		return e
	}
	expiryText, e := adText(entry, "accountExpires")
	if e != nil {
		return e
	}
	uac, e := strconv.ParseUint(uacText, 10, 32)
	if e != nil {
		return ErrDirectoryUnavailable
	}
	computed, e := strconv.ParseUint(computedText, 10, 32)
	if e != nil {
		return ErrDirectoryUnavailable
	}
	expiry, e := strconv.ParseUint(expiryText, 10, 63)
	if e != nil {
		return ErrDirectoryUnavailable
	}
	if uac&0x2 != 0 || computed&(0x10|0x800000) != 0 {
		return ErrProof
	}
	if expiry != 0 && expiry != uint64(1<<63-1) {
		seconds := int64(expiry/10000000) - 11644473600
		if !now.Before(time.Unix(seconds, 0)) {
			return ErrProof
		}
	}
	return nil
}
func (o *adOperation) accountResult(c *adConnection, domain string, entry *ldap.Entry) (*DirectoryAccount, error) {
	if e := adAccountActive(entry, time.Now().UTC()); e != nil {
		return nil, e
	}
	raw, e := adAttribute(entry, "objectGUID")
	if e != nil {
		return nil, e
	}
	id, e := ADGUID(raw)
	if e != nil {
		return nil, e
	}
	groups, e := o.groups(c, domain, entry)
	if e != nil {
		return nil, e
	}
	result := &DirectoryAccount{ForestGUID: o.config.Spec.ForestGUID, ObjectGUID: id, DN: entry.DN, GroupObjectGUIDs: groups, AccessGroupIDs: []string{}}
	result.UPN, _ = adText(entry, "userPrincipalName")
	result.DisplayName, _ = adText(entry, "displayName")
	accessGroups := map[string]bool{}
	for _, mapping := range o.config.Spec.GroupMappings {
		j := sort.SearchStrings(groups, mapping.GroupObjectGUID)
		if j < len(groups) && groups[j] == mapping.GroupObjectGUID {
			accessGroups[mapping.AccessGroupID] = true
		}
	}
	for id := range accessGroups {
		result.AccessGroupIDs = append(result.AccessGroupIDs, id)
	}
	sort.Strings(result.AccessGroupIDs)
	if o.ctx.Err() != nil {
		return nil, ErrDirectoryUnavailable
	}
	return result, nil
}
func (o *adOperation) groups(c *adConnection, domain string, entry *ldap.Entry) ([]string, error) {
	sids := entry.GetEqualFoldRawAttributeValues("tokenGroups")
	if len(sids) == 0 || len(sids) > o.config.Spec.MaximumGroups {
		return nil, ErrDirectoryUnavailable
	}
	seen := map[string]bool{}
	out := []string{}
	for _, sid := range sids {
		if len(sid) < 8 || len(sid) > 68 || int(sid[1])*4+8 != len(sid) || sid[0] != 1 || seen[string(sid)] {
			return nil, ErrDirectoryUnavailable
		}
		seen[string(sid)] = true
	}
	for start := 0; start < len(sids); start += 64 {
		end := min(start+64, len(sids))
		var filter strings.Builder
		filter.WriteString("(&(objectClass=group)(|")
		for _, sid := range sids[start:end] {
			filter.WriteString("(objectSid=" + adBinaryFilter(sid) + ")")
		}
		filter.WriteString("))")
		entries, e := o.search(c, domain, ldap.ScopeWholeSubtree, end-start, filter.String(), []string{"objectGUID", "objectSid", "groupType"})
		if e != nil || len(entries) != end-start {
			return nil, ErrDirectoryUnavailable
		}
		batch := map[string]bool{}
		wanted := map[string]bool{}
		for _, sid := range sids[start:end] {
			wanted[string(sid)] = true
		}
		for _, group := range entries {
			sid, e := adAttribute(group, "objectSid")
			if e != nil || !wanted[string(sid)] || batch[string(sid)] {
				return nil, ErrDirectoryUnavailable
			}
			batch[string(sid)] = true
			raw, e := adAttribute(group, "objectGUID")
			if e != nil {
				return nil, e
			}
			guid, e := ADGUID(raw)
			if e != nil {
				return nil, e
			}
			typ, e := adText(group, "groupType")
			if e != nil {
				return nil, e
			}
			n, e := strconv.ParseInt(typ, 10, 32)
			if e != nil || uint32(n)&0x80000000 == 0 {
				return nil, ErrDirectoryUnavailable
			}
			allowed := false
			dn, e := ldap.ParseDN(group.DN)
			if e != nil {
				return nil, ErrDirectoryUnavailable
			}
			for _, base := range o.config.Spec.GroupBaseDNs {
				parent, _ := ldap.ParseDN(base)
				if parent.EqualFold(dn) || parent.AncestorOfFold(dn) {
					allowed = true
				}
			}
			if allowed {
				out = append(out, guid)
			}
		}
	}
	sort.Strings(out)
	for i := 1; i < len(out); i++ {
		if out[i] == out[i-1] {
			return nil, ErrDirectoryUnavailable
		}
	}
	return out, nil
}
func (c *ADConnector) Validate(ctx context.Context, d DirectoryProviderDocument) (DirectoryValidation, error) {
	o, e := c.operation(ctx, d)
	if e != nil {
		return DirectoryValidation{}, e
	}
	defer o.close()
	connection, domain, e := o.service()
	if e != nil {
		return DirectoryValidation{}, e
	}
	defer connection.close()
	// Read the service principal itself: this exercises account attributes,
	// tokenGroups completeness and SID-to-GUID resolution without a user password.
	entries, e := o.search(connection, o.config.Spec.BindDN, ldap.ScopeBaseObject, 1, "(&(objectClass=user)(objectCategory=person))", adAccountAttrs)
	if e != nil || len(entries) != 1 {
		return DirectoryValidation{}, ErrDirectoryUnavailable
	}
	if _, e = o.accountResult(connection, domain, entries[0]); e != nil {
		return DirectoryValidation{}, ErrDirectoryUnavailable
	}
	// Every configured mapping must resolve to a security group under an allowed
	// group base, even if the service account is not a member of that group.
	for _, m := range o.config.Spec.GroupMappings {
		guid, e := adBinaryGUID(m.GroupObjectGUID)
		if e != nil {
			return DirectoryValidation{}, e
		}
		count := 0
		for _, base := range o.config.Spec.GroupBaseDNs {
			groups, e := o.search(connection, base, ldap.ScopeWholeSubtree, 2, "(&(objectClass=group)(objectGUID="+adBinaryFilter(guid)+"))", []string{"objectGUID", "groupType"})
			if e != nil {
				return DirectoryValidation{}, e
			}
			for _, group := range groups {
				typ, e := adText(group, "groupType")
				if e != nil {
					return DirectoryValidation{}, e
				}
				n, e := strconv.ParseInt(typ, 10, 32)
				if e != nil || uint32(n)&0x80000000 == 0 {
					return DirectoryValidation{}, ErrDirectoryUnavailable
				}
				count++
			}
		}
		if count != 1 {
			return DirectoryValidation{}, ErrDirectoryUnavailable
		}
	}
	if o.ctx.Err() != nil {
		return DirectoryValidation{}, ErrDirectoryUnavailable
	}
	out := DirectoryValidation{ForestGUID: o.config.Spec.ForestGUID}
	for _, name := range directoryChecks {
		out.Checks = append(out.Checks, DirectoryTestCheck{Name: name, State: "passed", ReasonCode: "verified"})
	}
	return out, nil
}
func (c *ADConnector) Authenticate(ctx context.Context, d DirectoryProviderDocument, login, password string) (*DirectoryAccount, error) {
	if login == "" || len(login) > 1024 || !utf8.ValidString(login) || strings.ContainsRune(login, 0) || password == "" || len(password) > 65536 {
		return nil, ErrProof
	}
	o, e := c.operation(ctx, d)
	if e != nil {
		return nil, e
	}
	defer o.close()
	connection, domain, e := o.service()
	if e != nil {
		return nil, e
	}
	defer connection.close()
	filter := "(&(objectCategory=person)(objectClass=user)(" + o.config.Spec.LoginAttribute + "=" + ldap.EscapeFilter(login) + "))"
	entry, e := o.account(connection, filter)
	if e != nil {
		return nil, e
	}
	if e = adAccountActive(entry, time.Now().UTC()); e != nil {
		return nil, e
	}
	// A separate connection to exactly the pinned TLS DC/IP. No retry follows a
	// user bind, including timeout or a lost response, to avoid lockout storms.
	user, e := o.dial(connection.endpoint, connection.ip, connection.tls)
	if e != nil {
		return nil, e
	}
	defer user.close()
	// MS-ADTS 5.1.1.1.1 name form 5 binds the objectGUID in braces.
	// The mutable DN is never used to select the password authentication subject.
	bindGUID, e := adAttribute(entry, "objectGUID")
	if e != nil {
		return nil, e
	}
	immutableName, e := ADGUID(bindGUID)
	if e != nil {
		return nil, e
	}
	if e = user.ldap.Bind("{"+immutableName+"}", password); e != nil {
		if ldap.IsErrorWithCode(e, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrProof
		}
		return nil, ErrDirectoryUnavailable
	}
	raw, e := adAttribute(entry, "objectGUID")
	if e != nil {
		return nil, e
	}
	again, e := o.account(connection, "(&(objectCategory=person)(objectClass=user)(objectGUID="+adBinaryFilter(raw)+"))")
	if e != nil {
		return nil, e
	}
	return o.accountResult(connection, domain, again)
}
func (c *ADConnector) LiveCheck(ctx context.Context, d DirectoryProviderDocument, objectGUID string) (*DirectoryAccount, error) {
	guid, e := adBinaryGUID(objectGUID)
	if e != nil {
		return nil, ErrProof
	}
	o, e := c.operation(ctx, d)
	if e != nil {
		return nil, e
	}
	defer o.close()
	connection, domain, e := o.service()
	if e != nil {
		return nil, e
	}
	defer connection.close()
	entry, e := o.account(connection, "(&(objectCategory=person)(objectClass=user)(objectGUID="+adBinaryFilter(guid)+"))")
	if e != nil {
		return nil, e
	}
	return o.accountResult(connection, domain, entry)
}

// The library decodes response lengths incrementally. Bound aggregate bytes
// before BER/TLS decoding without changing its process-global parser options.
type directoryReadBudget struct {
	net.Conn
	remaining *atomic.Int64
}

func (c *directoryReadBudget) Read(p []byte) (int, error) {
	remaining := c.remaining.Load()
	if remaining <= 0 {
		return 0, ErrDirectoryUnavailable
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, e := c.Conn.Read(p)
	if c.remaining.Add(-int64(n)) < 0 {
		return n, ErrDirectoryUnavailable
	}
	return n, e
}
