// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resources

import "embed"

//go:embed bundled/apps/*.yaml bundled/scripts/**/*.applescript
var FS embed.FS
