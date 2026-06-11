package dlp

import "testing"

func newDefault() *Scanner { return NewScanner(DefaultRules) }

// hasRule reports whether findings contain the given rule ID.
func hasRule(findings []Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestContentClass_Verilog(t *testing.T) {
	src := `
` + "`timescale 1ns/1ps" + `
module fifo #(parameter DEPTH = 16) (input clk, input rst_n, output reg full);
  reg [3:0] count;
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) count <= 4'd0;
  end
  assign full = (count == DEPTH);
endmodule
`
	f := newDefault().Scan(src)
	if !hasRule(f, "hdl-verilog") {
		t.Fatalf("expected hdl-verilog to fire, got %+v", f)
	}
}

func TestContentClass_Spice(t *testing.T) {
	src := `* opamp subcircuit
.subckt opamp vin vout vdd vss
.model nmos1 nmos level=54
.param vdd=1.8
.ends
`
	f := newDefault().Scan(src)
	if !hasRule(f, "spice-netlist") {
		t.Fatalf("expected spice-netlist to fire, got %+v", f)
	}
}

func TestContentClass_SDC(t *testing.T) {
	src := `create_clock -name clk -period 2.0 [get_ports clk]
set_input_delay 0.5 -clock clk [all_inputs]
`
	f := newDefault().Scan(src)
	if !hasRule(f, "sdc-constraints") {
		t.Fatalf("expected sdc-constraints to fire, got %+v", f)
	}
}

func TestTierB_ClassificationAndExport(t *testing.T) {
	src := `NORTHWIND SEMICONDUCTOR — COMPANY CONFIDENTIAL — TRADE SECRET
Export classification: ECCN 3A001 / EXPORT-CONTROLLED. Built on the TSMC N3 PDK.`
	f := newDefault().Scan(src)
	for _, id := range []string{"classification-marker", "export-control", "foundry-pdk"} {
		if !hasRule(f, id) {
			t.Errorf("expected %s to fire, got %+v", id, f)
		}
	}
}

// Tapeout streams must be caught by their FORMAT magic, regardless of
// filename/path — this is what defeats the "move it to an allowed dir" bypass.
func TestTapeoutFormatDetection(t *testing.T) {
	s := newDefault()
	// GDSII HEADER record magic: 00 06 00 02 then a version int.
	gds := string([]byte{0x00, 0x06, 0x00, 0x02, 0x00, 0x05}) + "BGNLIB"
	if f := s.Scan(gds); !hasRule(f, "tapeout-stream") {
		t.Errorf("GDSII magic should fire tapeout-stream, got %+v", f)
	}
	oasis := "%SEMI-OASIS\r\n\x00\x80somethingbinary"
	if f := s.Scan(oasis); !hasRule(f, "tapeout-stream") {
		t.Errorf("OASIS magic should fire tapeout-stream, got %+v", f)
	}
}

func TestTierC_Secrets(t *testing.T) {
	src := `aws_access_key_id = AKIAIOSFODNN7EXAMPLE
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA
-----END RSA PRIVATE KEY-----`
	f := newDefault().Scan(src)
	if !hasRule(f, "aws-access-key") {
		t.Errorf("expected aws-access-key to fire, got %+v", f)
	}
	if !hasRule(f, "private-key-block") {
		t.Errorf("expected private-key-block to fire, got %+v", f)
	}
}

// Clean files must PASS — the scalpel-not-sledgehammer guarantee. If these
// trip, the demo loses credibility with a security buyer.
func TestCleanFilesPass(t *testing.T) {
	clean := map[string]string{
		"readme": "# northwind-webapp\n\nA small storefront. MIT licensed. `npm install` then `npm run dev`.\n",
		"python": "def greet(name: str) -> str:\n    return f\"hello, {name}\"\n\nprint(greet(\"world\"))\n",
		"ts":     "export function total(items: number[]): number {\n  return items.reduce((a, b) => a + b, 0);\n}\n",
		"notes":  "Sprint planning: ship the cart redesign, fix the checkout bug, update the docs.\n",
		"prose":  "Can you explain what a module does in general software terms and how to assign a value?\n",
	}
	s := newDefault()
	for name, body := range clean {
		if f := s.Scan(body); len(f) > 0 {
			t.Errorf("clean file %q should pass but matched: %+v", name, f)
		}
	}
}

// A single passing mention of an HDL keyword must NOT trip content-class
// (MinHits guard) — only real source with multiple signals should.
func TestSingleKeywordDoesNotTripHDL(t *testing.T) {
	src := "In Verilog, the `endmodule` keyword closes a module definition."
	if f := newDefault().Scan(src); hasRule(f, "hdl-verilog") {
		t.Errorf("single HDL keyword mention should not fire hdl-verilog, got %+v", f)
	}
}

func TestPrimaryReasonPrefersContentClass(t *testing.T) {
	findings := []Finding{
		{RuleID: "us-ssn", Category: CategoryPII, RuleName: "US SSN"},
		{RuleID: "hdl-verilog", Category: CategoryContentClass, RuleName: "Verilog / SystemVerilog source"},
	}
	got := PrimaryReason(findings)
	want := "proprietary source/IP detected (Verilog / SystemVerilog source)"
	if got != want {
		t.Errorf("PrimaryReason = %q, want %q", got, want)
	}
}
