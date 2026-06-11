// openscope-mint — small CLI that generates a new API token + its prefix
// and HMAC hash. Used by scripts/seed_test_keys.sh and as a building block
// for Stage 7's admin endpoint. Reads pepper from OPENSCOPE_AUTH_PEPPER.
//
// Usage:
//
//	OPENSCOPE_AUTH_PEPPER=... openscope-mint --role developer
//
// Output (machine-parseable):
//
//	TOKEN=osk_developer_xxxxxxxxxxxxxxxxxxxxxx
//	PREFIX=osk_develope
//	HASH_HEX=ab12cd34...
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/openscope/openscope/router/internal/tenancy"
)

func main() {
	role := flag.String("role", "", "developer|it|engineer|admin (required)")
	flag.Parse()

	if *role == "" {
		fmt.Fprintln(os.Stderr, "--role is required")
		os.Exit(2)
	}

	pepper := os.Getenv("OPENSCOPE_AUTH_PEPPER")
	if pepper == "" {
		fmt.Fprintln(os.Stderr, "OPENSCOPE_AUTH_PEPPER required")
		os.Exit(2)
	}

	token, prefix, hash, err := tenancy.Mint(*role, []byte(pepper))
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint:", err)
		os.Exit(1)
	}

	fmt.Printf("TOKEN=%s\n", token)
	fmt.Printf("PREFIX=%s\n", prefix)
	fmt.Printf("HASH_HEX=%s\n", hex.EncodeToString(hash))
}
