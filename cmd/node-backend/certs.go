package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Certificate delivery (build plan §12 slice 7): the panel ships its
// issued certificates inside GET /api/v1/node/config as a certs
// array ({ref, crt, key} PEM bodies, one entry per certificate
// referenced by this node's TLS inbounds). The agent writes them to
// <config-dir>/certs/<ref>.crt + <ref>.key (mode 0600, atomic rename
// via writeFileAtomic) on the existing 60 s pull chain — no new
// background task or poll. The cores read the files by path, so a
// renewal (same ref, new PEM) changes no rendered config: the apply
// path must treat a certificate content change as a reload trigger
// (see syncCerts' changed set and the certChanged flags in run.go),
// otherwise a renewal would sit on disk unused until the next
// inbound change.
//
// Stale files are deliberately left on disk: a certificate that is
// no longer referenced is never loaded by either core (both renderers
// only reference files for CertRefs present in the current inbounds),
// and deleting on an empty certs list would wipe previously delivered
// certificates if an older panel (or a transient panel omission)
// sends none. Private-key hygiene is preserved by the 0600 mode and
// the certs directory itself, which already holds the node's own
// client key at the same permissions.
func (a *configApplier) syncCerts(nc *nodeConfig) (map[int64]bool, error) {
	dir := a.certsDir()
	changed := map[int64]bool{}
	for _, c := range nc.Certs {
		if c.Ref <= 0 {
			log.Printf("certificate entry with invalid ref %d ignored", c.Ref)
			continue
		}
		crt := strings.TrimSpace(c.Crt)
		key := strings.TrimSpace(c.Key)
		if crt == "" || key == "" {
			log.Printf("certificate ref %d ignored: empty crt or key", c.Ref)
			continue
		}
		// Fail closed before touching disk or any core: a bad PEM
		// pair (unparseable, or crt/key mismatch) aborts the whole
		// apply, so the running cores keep serving the old
		// certificate and the next pull retries.
		if _, err := tls.X509KeyPair([]byte(crt), []byte(key)); err != nil {
			return nil, fmt.Errorf("certificate ref %d: invalid PEM pair: %w", c.Ref, err)
		}
		for _, f := range []struct {
			path string
			body string
		}{
			{filepath.Join(dir, fmt.Sprintf("%d.crt", c.Ref)), crt + "\n"},
			{filepath.Join(dir, fmt.Sprintf("%d.key", c.Ref)), key + "\n"},
		} {
			existing, err := os.ReadFile(f.path)
			if err == nil && bytes.Equal(existing, []byte(f.body)) {
				continue
			}
			if err := writeFileAtomic(f.path, []byte(f.body), 0o600); err != nil {
				return nil, fmt.Errorf("write certificate file %s: %w", f.path, err)
			}
			changed[c.Ref] = true
		}
		if changed[c.Ref] {
			log.Printf("certificate ref %d written to %s", c.Ref, dir)
		}
	}
	return changed, nil
}

// xrayTLSRefs returns the CertRefs of this config's enabled Xray TLS
// inbounds (VLESS over TCP+TLS and Trojan over TCP+TLS): the set a
// certificate change must intersect to force an Xray reload.
func xrayTLSRefs(nc *nodeConfig) map[int64]bool {
	refs := map[int64]bool{}
	for _, in := range nc.Inbounds {
		if !in.Enabled || strings.ToLower(in.Security) != "tls" || strings.ToLower(in.Transport) != "tcp" {
			continue
		}
		switch strings.ToLower(in.Protocol) {
		case "vless", "trojan":
			if in.CertRef > 0 {
				refs[in.CertRef] = true
			}
		}
	}
	return refs
}

// singboxTLSRefs returns the CertRefs of this config's enabled
// sing-box TLS inbounds (HY2 / TUIC / AnyTLS): the set a certificate
// change must intersect to force a sing-box reload.
func singboxTLSRefs(nc *nodeConfig) map[int64]bool {
	refs := map[int64]bool{}
	for _, in := range nc.Inbounds {
		if !in.Enabled {
			continue
		}
		switch strings.ToLower(in.Protocol) {
		case "hysteria2", "tuic", "anytls":
			if in.CertRef > 0 {
				refs[in.CertRef] = true
			}
		}
	}
	return refs
}

// certChangeAffects reports whether any changed certificate ref is
// used by the given inbound set.
func certChangeAffects(changed, used map[int64]bool) bool {
	for ref := range changed {
		if used[ref] {
			return true
		}
	}
	return false
}
