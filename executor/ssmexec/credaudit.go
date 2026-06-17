// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ssmexec

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// CredWarning is a machine-readable finding about the broker's AWS credential
// custody — the SSM analog of sshexec.KeyWarning.
type CredWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

const (
	CredNotRootOwned = "cred_not_root_owned" // credentials file owned by a non-root uid
	CredModeTooOpen  = "cred_mode_too_open"  // credentials file readable beyond its owner
)

// AgentAccessible reports whether a code means the broker's AWS credentials file
// is readable by the agent's (non-root) user. That lets the agent call `aws ssm`
// directly and bypass the broker — exactly what an agent-readable SSH key would
// allow — so the executor REFUSES on these, just as sshexec refuses an
// agent-accessible key. (Custody of the broker's credential is necessary but not
// sufficient; the binding control is that the agent's OWN AWS identity is denied
// SSM in IAM — which lives in AWS, not here.)
func AgentAccessible(code string) bool {
	switch code {
	case CredNotRootOwned, CredModeTooOpen:
		return true
	}
	return false
}

// resolveCredFile returns the AWS shared-credentials file the CLI would read:
// AWS_SHARED_CREDENTIALS_FILE wins, else ~/.aws/credentials.
func resolveCredFile() string {
	if v := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".aws", "credentials")
}

// AuditCredCustody checks that the broker's AWS credentials are not agent-
// readable. When a credentials FILE is in use it must be root-owned and 0600
// (mirroring keyaudit). No such file — env-only creds in the root daemon's
// process, or the EC2 instance role — is treated as custodied: the agent can't
// read another process's environment, and IMDS lockdown is a deployment concern.
// This assumes the daemon runs as root (the privileged-helper model). The check
// is conservative: an agent-readable credentials file is flagged even if the
// broker actually uses the instance role, because the agent could still use that
// file to reach SSM directly.
func AuditCredCustody(credFile string) []CredWarning {
	if credFile == "" {
		return nil
	}
	info, err := os.Stat(credFile)
	if err != nil || !info.Mode().IsRegular() {
		return nil // no usable file → env creds or instance role
	}

	var out []CredWarning
	if info.Mode().Perm()&0o077 != 0 {
		out = append(out, CredWarning{
			Code:    CredModeTooOpen,
			Message: fmt.Sprintf("AWS credentials %q have mode %04o; must be 0600 so non-root processes can't read them", credFile, info.Mode().Perm()),
		})
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
		out = append(out, CredWarning{
			Code: CredNotRootOwned,
			Message: fmt.Sprintf(
				"AWS credentials %q are owned by uid %d, not root — the agent can read them and call SSM directly; move them to a root-owned path (e.g. /var/openscope/aws/credentials referenced by AWS_SHARED_CREDENTIALS_FILE), or use the EC2 instance role",
				credFile, stat.Uid),
		})
	}
	return out
}
