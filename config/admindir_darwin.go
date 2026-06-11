// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package config

// AdminDir is the machine-wide admin config directory (root-owned;
// override with OPENSCOPE_ADMIN_DIR).
const AdminDir = "/Library/Application Support/OpenScope"
