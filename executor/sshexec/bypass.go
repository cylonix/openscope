// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sshexec

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/executor"
)

// Bypass-probe outcomes.
const (
	BypassFound   = "bypass"       // a user key authenticated to the target
	BypassClear   = "clear"        // auth refused — no parallel path via this key
	BypassUnknown = "inconclusive" // host unreachable / other error — undetermined
)

// BypassResult is one (target, identity) probe outcome.
type BypassResult struct {
	Target  string `json:"target"`
	Host    string `json:"host"`
	Key     string `json:"key"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// DiscoverUserKeys returns the private-key files in <homeDir>/.ssh that an
// unprivileged agent could use directly: every file with a ".pub" sibling.
// These are the keys whose reach to a brokered server would bypass the broker;
// the public keys and other ~/.ssh contents (config, known_hosts) are ignored.
func DiscoverUserKeys(homeDir string) []string {
	if homeDir == "" {
		return nil
	}
	sshDir := filepath.Join(homeDir, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}
	var keys []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".pub") {
			continue
		}
		priv := filepath.Join(sshDir, strings.TrimSuffix(name, ".pub"))
		if info, err := os.Stat(priv); err == nil && !info.IsDir() {
			keys = append(keys, priv)
		}
	}
	sort.Strings(keys)
	return keys
}

// ProbeBypass attempts to authenticate to target using ONLY each of userKeys
// (never the broker's key), in batch mode. A key that authenticates proves the
// agent has an independent path to the host — the broker is bypassable. The
// only remote command run is the harmless `true`; nothing on the target is read
// or written.
//
// run executes ssh; pass nil for the default os/exec runner. This opens a real
// network connection to the target, so callers must invoke it only on explicit
// user request, never as a side effect of a routine check.
func ProbeBypass(target admin.SSHTarget, userKeys []string, run CommandRunner) []BypassResult {
	if run == nil {
		run = execRunner{}
	}
	port := target.Port
	if port == 0 {
		port = 22
	}
	dest := target.Host
	if target.User != "" {
		dest = target.User + "@" + target.Host
	}
	out := make([]BypassResult, 0, len(userKeys))
	for _, key := range userKeys {
		args := []string{
			"-o", "BatchMode=yes",
			"-o", "IdentitiesOnly=yes",
			"-o", "PreferredAuthentications=publickey",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=5",
			"-i", key,
			"-p", strconv.Itoa(port),
		}
		if target.ProxyJump != "" {
			args = append(args, "-J", target.ProxyJump)
		}
		args = append(args, dest, "true")

		res, err := run.Run("ssh", args, nil)
		out = append(out, classifyBypass(target, key, res, err))
	}
	return out
}

// classifyBypass maps an ssh probe's result to an outcome. ssh exits 0 only
// after authenticating and running `true`; a publickey rejection exits 255 with
// "Permission denied"; anything else (timeout, refused, DNS) is undetermined.
func classifyBypass(target admin.SSHTarget, key string, res executor.Result, err error) BypassResult {
	r := BypassResult{Target: target.Alias, Host: target.Host, Key: key}
	switch {
	case err != nil:
		r.Outcome, r.Detail = BypassUnknown, err.Error()
	case res.ExitCode == 0:
		r.Outcome = BypassFound
	case strings.Contains(res.Stderr, "Permission denied") || strings.Contains(res.Stderr, "publickey"):
		r.Outcome = BypassClear
	default:
		r.Outcome, r.Detail = BypassUnknown, firstLine(res.Stderr)
	}
	return r
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if before, _, found := strings.Cut(s, "\n"); found {
		return strings.TrimSpace(before)
	}
	return s
}

// --- Inspection-based bypass check (no failed auths) --------------------------
//
// ProbeBypass above proves rejection by ATTEMPTING auth with each personal key —
// which logs a failed publickey on the target and, on the many hosts running
// fail2ban / sshguard / CrowdSec, gets the operator's IP banned. That doesn't
// scale (you can't allowlist the broker on every target before it runs).
// InspectAuthorizedKeys answers the same question with NO failed auth: it connects
// once with the broker's own (authorized) key, reads the target's authorized_keys,
// and checks whether any personal key's fingerprint is present. Connecting with
// the broker key requires reading target.IdentityFile (root-owned), so callers run
// this where they can (apply, as root) and defer where they can't (plan, as the
// user) — never falling back to an auth attempt.

// authKeysSentinel separates the authorized_keys dump from the sshd_config probe.
const authKeysSentinel = "__OPENSCOPE_SSHD__"

// authKeysReadCmd, run on the target over the broker connection, prints every
// readable authorized_keys file (connecting user + root + /home/*) then, after the
// sentinel, any sshd_config directive that could admit a key NOT listed in
// authorized_keys (CA trust, a command, or a relocated AuthorizedKeysFile).
// Read-only; writes nothing.
const authKeysReadCmd = `for f in "$HOME"/.ssh/authorized_keys "$HOME"/.ssh/authorized_keys2 /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2; do [ -r "$f" ] && cat "$f" 2>/dev/null; done; echo ` + authKeysSentinel + `; cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -iE '^[[:space:]]*(AuthorizedKeysFile|TrustedUserCAKeys|AuthorizedKeysCommand)[[:space:]]' || true`

// WithinBrokerKeyDir reports whether path is inside the broker's root-owned key dir
// (brokerSSHDir). The inspect_bypass daemon op uses it as a custody gate: it will only
// connect with an identity file under this dir, so a caller passing proposed target
// details can't make the daemon authenticate with an arbitrary (e.g. root's personal)
// key. Legitimate brokered targets keep their keys here per the custody rule.
func WithinBrokerKeyDir(path string) bool {
	if path == "" {
		return false
	}
	clean := filepath.Clean(path)
	return clean == brokerSSHDir || strings.HasPrefix(clean, brokerSSHDir+string(filepath.Separator))
}

// ReadAuthorizedKeys connects to target with the broker's key (a successful,
// authorized login — no failed-publickey line for fail2ban to count) and returns the
// raw authorized_keys + sshd_config dump (the read-only authKeysReadCmd output). It
// is the PRIVILEGED half of the bypass inspection and must run where the broker key
// is readable: the root daemon (via the inspect_bypass built-in), or apply-as-root.
// ok=false with a one-line detail when the connection or read fails.
func ReadAuthorizedKeys(target admin.SSHTarget, run CommandRunner) (dump string, ok bool, detail string) {
	if run == nil {
		run = execRunner{}
	}
	port := target.Port
	if port == 0 {
		port = 22
	}
	knownHosts := filepath.Join(brokerSSHDir, "known_hosts")
	_ = os.MkdirAll(brokerSSHDir, 0o700) // best-effort; the root daemon owns it
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "ConnectTimeout=8",
		"-p", strconv.Itoa(port),
	}
	if target.IdentityFile != "" {
		args = append(args, "-i", target.IdentityFile)
	}
	if target.ProxyJump != "" {
		args = append(args, "-J", target.ProxyJump)
	}
	args = append(args, target.User+"@"+target.Host, authKeysReadCmd)

	res, err := run.Run("ssh", args, nil)
	if err != nil || res.ExitCode != 0 {
		d := strings.TrimSpace(res.Stderr)
		if err != nil {
			d = err.Error()
		}
		return "", false, firstLine(d)
	}
	return res.Stdout, true, ""
}

// UserKey pairs a personal key's display path with its SHA256 public-key fingerprint.
// The CLI computes these from its OWN ~/.ssh/*.pub files and hands them to the daemon,
// so the comparison runs inside the daemon and the target's authorized_keys never
// leaves it — only the per-key verdict does. A fingerprint is derived from a public
// key; it carries no secret.
type UserKey struct {
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"` // "" if the .pub could not be read
}

// LocalUserKeys reads each private-key path's ".pub" sibling and returns its
// fingerprint. Runs on the operator's machine; no private material is read.
func LocalUserKeys(privKeyPaths []string) []UserKey {
	out := make([]UserKey, 0, len(privKeyPaths))
	for _, p := range privKeyPaths {
		fp, _ := localKeyFingerprint(p) // "" when the .pub is unreadable
		out = append(out, UserKey{Path: p, Fingerprint: fp})
	}
	return out
}

// InspectBypass reads target's authorized_keys via the broker key and reports, for each
// UserKey, whether it is authorized there (a path that bypasses the broker). The read
// AND the compare happen here, so authorized_keys is never returned, only the verdict:
//
//   - fingerprint present in authorized_keys           -> BypassFound
//   - absent, no CA/command/relocated key file          -> BypassClear
//   - absent, but such alternate auth IS configured     -> BypassUnknown
//   - broker key won't connect / read fails             -> BypassUnknown
//
// Runs in the daemon (root, holds the broker key) for plan/check-bypass, and locally
// for apply-as-root. nil run selects the default os/exec runner.
func InspectBypass(target admin.SSHTarget, keys []UserKey, run CommandRunner) []BypassResult {
	dump, ok, detail := ReadAuthorizedKeys(target, run)
	if !ok {
		detail = "could not read authorized_keys via the broker key: " + detail
		out := make([]BypassResult, 0, len(keys))
		for _, k := range keys {
			out = append(out, BypassResult{Target: target.Alias, Host: target.Host, Key: k.Path, Outcome: BypassUnknown, Detail: detail})
		}
		return out
	}
	authorized, hasAltAuth := parseAuthorizedKeys(dump)
	out := make([]BypassResult, 0, len(keys))
	for _, k := range keys {
		r := BypassResult{Target: target.Alias, Host: target.Host, Key: k.Path}
		switch {
		case k.Fingerprint == "":
			r.Outcome, r.Detail = BypassUnknown, "could not fingerprint local public key "+k.Path+".pub"
		case authorized[k.Fingerprint]:
			r.Outcome = BypassFound
		case hasAltAuth:
			r.Outcome, r.Detail = BypassUnknown, "key not in authorized_keys, but CA/command-based auth is configured on the target — run the explicit live-auth check to be certain"
		default:
			r.Outcome = BypassClear
		}
		out = append(out, r)
	}
	return out
}

// InspectAuthorizedKeys is the local-read wrapper: it fingerprints userKeys' .pub files
// here and inspects in one call. Used by apply-as-root and `ssh check-bypass` as root,
// where the broker key is readable locally.
func InspectAuthorizedKeys(target admin.SSHTarget, userKeys []string, run CommandRunner) []BypassResult {
	return InspectBypass(target, LocalUserKeys(userKeys), run)
}

// parseAuthorizedKeys splits the remote dump on the sentinel: the SHA256
// fingerprints of every authorized public key, and whether the sshd config admits
// keys outside authorized_keys (CA, command, or a relocated key file).
func parseAuthorizedKeys(stdout string) (fingerprints map[string]bool, hasAltAuth bool) {
	keysPart, cfgPart, _ := strings.Cut(stdout, authKeysSentinel)
	fingerprints = map[string]bool{}
	for _, line := range strings.Split(keysPart, "\n") {
		if fp, ok := sshKeyFingerprint(line); ok {
			fingerprints[fp] = true
		}
	}
	cfg := strings.ToLower(cfgPart)
	if strings.Contains(cfg, "trustedusercakeys") || strings.Contains(cfg, "authorizedkeyscommand") {
		hasAltAuth = true
	}
	// A relocated AuthorizedKeysFile means our standard-location read may have
	// missed the real file — treat absence as inconclusive, not clear.
	if strings.Contains(cfg, "authorizedkeysfile") && !strings.Contains(cfg, ".ssh/authorized_keys") {
		hasAltAuth = true
	}
	return fingerprints, hasAltAuth
}

// localKeyFingerprint returns the SHA256 fingerprint of privKeyPath's public
// sibling (privKeyPath + ".pub"). No private-key material is read.
func localKeyFingerprint(privKeyPath string) (string, bool) {
	data, err := os.ReadFile(privKeyPath + ".pub")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if fp, ok := sshKeyFingerprint(line); ok {
			return fp, true
		}
	}
	return "", false
}

// sshKeyFingerprint computes the OpenSSH SHA256 fingerprint of one
// authorized_keys/.pub line — base64(sha256(wire-format key blob)), unpadded, the
// same string `ssh-keygen -lf` prints. Options before the key type are tolerated;
// cert and unknown types are ignored.
func sshKeyFingerprint(line string) (string, bool) {
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if !isSSHKeyType(fields[i]) {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[i+1])
		if err != nil || len(blob) == 0 {
			continue
		}
		sum := sha256.Sum256(blob)
		return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), true
	}
	return "", false
}

func isSSHKeyType(s string) bool {
	switch s {
	case "ssh-ed25519", "ssh-rsa", "ssh-dss",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
		return true
	}
	return false
}
