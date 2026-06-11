// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package config

// AdminDir is the machine-wide admin config directory (root-owned;
// override with OPENSCOPE_ADMIN_DIR). On Linux the broker reads its
// ssh_targets.yaml / http_profiles.yaml / system_commands.yaml from here.
const AdminDir = "/etc/openscope"
