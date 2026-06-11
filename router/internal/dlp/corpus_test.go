package dlp

import (
	"os"
	"path/filepath"
	"testing"
)

// corpusRoot is the samples/ dir relative to pkg/dlp.
const corpusRoot = "../../samples"

// TestCorpusRestrictedAllDeny verifies every file in northwind-rtl produces at
// least one finding (DENY), and that the named rule fires where we assert it.
func TestCorpusRestrictedAllDeny(t *testing.T) {
	cases := []struct {
		path     string
		mustFire string // a rule ID we require to be present
	}{
		{"northwind-rtl/rtl/aes_sbox.sv", "hdl-verilog"},
		{"northwind-rtl/rtl/async_fifo.v", "hdl-verilog"},
		{"northwind-rtl/analog/bandgap_ref.sp", "spice-netlist"},
		{"northwind-rtl/constraints/falcon_top.sdc", "sdc-constraints"},
		{"northwind-rtl/ip/licensed_phy.v", "encrypted-ip-pragma"},
		{"northwind-rtl/docs/design_spec.md", "classification-marker"},
		{"northwind-rtl/docs/export_notice.txt", "export-control"},
		{"northwind-rtl/docs/pdk_notes.txt", "foundry-pdk"},
		{"northwind-rtl/scripts/run_synth.tcl", "aws-access-key"},
	}
	s := newDefault()
	for _, c := range cases {
		body := readCorpus(t, c.path)
		findings := s.Scan(body)
		if len(findings) == 0 {
			t.Errorf("%s: expected DENY (findings) but got none", c.path)
			continue
		}
		if !hasRule(findings, c.mustFire) {
			t.Errorf("%s: expected rule %q to fire; got %v", c.path, c.mustFire, RuleIDs(findings))
		}
	}
}

// TestCorpusAllowedAllPass verifies every file in northwind-webapp is clean.
func TestCorpusAllowedAllPass(t *testing.T) {
	paths := []string{
		"northwind-webapp/src/cart.ts",
		"northwind-webapp/src/hello.py",
		"northwind-webapp/docs/notes.txt",
	}
	s := newDefault()
	for _, p := range paths {
		body := readCorpus(t, p)
		if findings := s.Scan(body); len(findings) > 0 {
			t.Errorf("%s: expected ALLOW (clean) but matched %v", p, RuleIDs(findings))
		}
	}
}

func readCorpus(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpusRoot, rel))
	if err != nil {
		t.Fatalf("read corpus file %s: %v", rel, err)
	}
	return string(b)
}
