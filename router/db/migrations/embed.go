// Package migrations embeds the SQL schema migrations so
// cmd/openscope-migrate ships them inside the binary — no psql or checkout
// needed on the deploy host.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
