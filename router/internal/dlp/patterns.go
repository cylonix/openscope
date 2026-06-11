package dlp

import "regexp"

// Category groups rules by what they protect against. The router uses it to
// explain a block ("proprietary HDL detected") and the dashboards group
// findings by category. All categories block by default — the demo's posture
// is "proprietary source, IP markers, secrets, and export-controlled material
// never leave the perimeter," independent of which workspace claimed to send
// them (so a mislabeled repo can't smuggle RTL past the gate).
const (
	CategoryContentClass   = "content-class"  // the payload *is* proprietary technical artifact (HDL/SPICE/netlist/SDC/layout)
	CategoryClassification = "classification" // confidentiality markers / banners
	CategoryExportControl  = "export-control" // ITAR / EAR / ECCN
	CategoryFoundry        = "foundry-nda"    // PDK / foundry identifiers under NDA
	CategorySecret         = "secret"         // credentials, private keys, encrypted-IP markers
	CategoryPII            = "pii"            // SSN / payment card
)

// Rule is one DLP pattern. ID is the stable identifier we audit (stored in
// app.router_events.dlp_rule_ids and surfaced in the demo UI). Name is the
// human-readable label. Category groups the rule for the UI and the block
// reason. MinHits is the number of distinct pattern hits required before the
// rule fires — content-class rules use MinHits>1 so a single stray keyword
// (e.g. someone *asking about* `endmodule`) doesn't trip them, while a real
// source file with many signals does. MinHits<=1 means "any single match".
type Rule struct {
	ID       string
	Name     string
	Category string
	Pattern  *regexp.Regexp
	Severity string // "critical" | "high" | "medium" | "low"
	MinHits  int
}

// DefaultRules is the layered IP-exfiltration rule set, tuned for a chip /
// semiconductor design org. Three tiers:
//
//	Tier A — content-class: detect that the payload *is* proprietary technical
//	         artifact (Verilog/SystemVerilog, VHDL, SPICE, gate/Liberty netlist,
//	         SDC constraints, LEF/DEF/GDSII layout). This is the headline: an
//	         engineer pasting RTL into a coding agent is stopped at the
//	         perimeter. MinHits>1 keeps precision high.
//	Tier B — classification + export markers: the banners real companies stamp
//	         (COMPANY CONFIDENTIAL, TRADE SECRET) and export-control terms
//	         (ITAR, EAR99, ECCN) plus foundry/PDK NDA identifiers.
//	Tier C — secrets: cloud keys, private-key blocks, API tokens, IEEE-1735
//	         encrypted-IP pragmas, and basic PII (SSN, card) for completeness.
//
// Everything here is deterministic regex — the industry-correct approach for
// source/document leak (Purview, Nightfall, gitleaks all work this way). No
// faked ML. Customers add their own rules (and exact-data-match fingerprinting
// of registered crown-jewel files) in v1.x.
var DefaultRules = []Rule{
	// ----- Tier A: content-class -------------------------------------------
	{
		ID:       "hdl-verilog",
		Name:     "Verilog / SystemVerilog source",
		Category: CategoryContentClass,
		// endmodule / always_ff / `timescale etc. are near-unique to HDL.
		Pattern:  regexp.MustCompile(`(?im)(\bendmodule\b|\balways_ff\b|\balways_comb\b|\balways_latch\b|\balways\s*@|\x60timescale\b|\binitial\s+begin\b|\breg\s*\[|\bwire\s*\[|\bassign\s+\w+\s*=|\bmodule\s+\w+\s*[#(;])`),
		Severity: "high",
		MinHits:  2,
	},
	{
		ID:       "hdl-vhdl",
		Name:     "VHDL source",
		Category: CategoryContentClass,
		Pattern:  regexp.MustCompile(`(?im)(\bentity\s+\w+\s+is\b|\barchitecture\s+\w+\s+of\b|\bport\s*\(|\bstd_logic(_vector)?\b|\bsignal\s+\w+\s*:|\bprocess\s*\()`),
		Severity: "high",
		MinHits:  2,
	},
	{
		ID:       "spice-netlist",
		Name:     "SPICE netlist / device model",
		Category: CategoryContentClass,
		Pattern:  regexp.MustCompile(`(?im)^\s*\.(subckt|ends|model|tran|ac|dc|op|param|include|lib|global|measure|probe|nodeset)\b`),
		Severity: "high",
		MinHits:  2,
	},
	{
		ID:       "liberty-netlist",
		Name:     "Liberty / gate-level netlist",
		Category: CategoryContentClass,
		Pattern:  regexp.MustCompile(`(?im)^\s*(library|cell|pin|timing|pg_pin|leakage_power|internal_power)\s*\(`),
		Severity: "high",
		MinHits:  2,
	},
	{
		ID:       "sdc-constraints",
		Name:     "Synopsys design constraints (SDC)",
		Category: CategoryContentClass,
		Pattern:  regexp.MustCompile(`(?i)\b(create_clock|set_input_delay|set_output_delay|set_clock_uncertainty|set_clock_groups|set_false_path|set_multicycle_path|set_max_delay|set_propagated_clock|current_design)\b`),
		Severity: "high",
		MinHits:  1,
	},
	{
		ID:       "layout-lef-def-gds",
		Name:     "Physical layout (LEF/DEF/GDSII)",
		Category: CategoryContentClass,
		Pattern:  regexp.MustCompile(`(?im)(^\s*DIEAREA\b|^\s*COMPONENTS\s+\d|^\s*MACRO\s+\w+|^\s*END\s+LIBRARY\b|\bGDSII\b|^\s*UNITS\s+DISTANCE\s+MICRONS\b)`),
		Severity: "critical",
		MinHits:  1,
	},
	{
		// Tapeout / mask layout detected by the FORMAT's own bytes, not by
		// filename or path — so renaming a .gds to .txt or moving it to an
		// "allowed" directory doesn't bypass it. GDSII files begin with the
		// HEADER record magic 00 06 00 02; OASIS streams begin with the
		// "%SEMI-OASIS" magic string.
		ID:       "tapeout-stream",
		Name:     "Tapeout mask layout (GDSII/OASIS stream)",
		Category: CategoryContentClass,
		Pattern:  regexp.MustCompile(`(?s)(\A\x00\x06\x00\x02|\A%SEMI-OASIS|%SEMI-OASIS\r?\n)`),
		Severity: "critical",
		MinHits:  1,
	},

	// ----- Tier B: classification + export + foundry -----------------------
	{
		ID:       "classification-marker",
		Name:     "Confidentiality / classification marker",
		Category: CategoryClassification,
		Pattern:  regexp.MustCompile(`(?i)(COMPANY\s+CONFIDENTIAL|STRICTLY\s+CONFIDENTIAL|TRADE\s+SECRET|PROPRIETARY\s+AND\s+CONFIDENTIAL|INTERNAL\s+USE\s+ONLY|RESTRICTED\s+DISTRIBUTION|CONFIDENTIAL\s+DESIGN|NOT\s+FOR\s+EXTERNAL\s+(USE|DISTRIBUTION))`),
		Severity: "high",
		MinHits:  1,
	},
	{
		ID:       "export-control",
		Name:     "Export-control marker (ITAR/EAR/ECCN)",
		Category: CategoryExportControl,
		Pattern:  regexp.MustCompile(`(?i)(\bITAR\b|\bEAR99\b|\bECCN\b|\bEXPORT[\s-]CONTROLLED\b|\b3A001\b|\bexport\s+administration\s+regulations\b)`),
		Severity: "critical",
		MinHits:  1,
	},
	{
		ID:       "foundry-pdk",
		Name:     "Foundry / PDK identifier (NDA)",
		Category: CategoryFoundry,
		Pattern:  regexp.MustCompile(`(?i)(\bTSMC\b|\bGlobalFoundries\b|\bSamsung\s+Foundry\b|\bSMIC\b|\bprocess\s+design\s+kit\b|\bPDK\b|\b[NT][0-9]{1,2}\s*(nm)?\s+(node|process|PDK)|\b(3|5|7|16|28)\s*nm\s+(node|process|PDK))`),
		Severity: "high",
		MinHits:  1,
	},

	// ----- Tier C: secrets + PII -------------------------------------------
	{
		ID:       "aws-access-key",
		Name:     "AWS access key",
		Category: CategorySecret,
		Pattern:  regexp.MustCompile(`\bA(?:KIA|SIA|GPA|IDA|IPA|NPA|NVA|PKA|ROA|SCA|3T)[0-9A-Z]{16}\b`),
		Severity: "critical",
		MinHits:  1,
	},
	{
		ID:       "private-key-block",
		Name:     "PEM private key block",
		Category: CategorySecret,
		Pattern:  regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
		Severity: "critical",
		MinHits:  1,
	},
	{
		ID:       "api-token",
		Name:     "API token / bearer secret",
		Category: CategorySecret,
		Pattern:  regexp.MustCompile(`(?i)(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{40,}|xox[baprs]-[0-9A-Za-z-]{10,}|sk-[A-Za-z0-9]{20,})`),
		Severity: "high",
		MinHits:  1,
	},
	{
		ID:       "encrypted-ip-pragma",
		Name:     "IEEE-1735 encrypted IP (licensed)",
		Category: CategorySecret,
		Pattern:  regexp.MustCompile(`(?i)(\x60pragma\s+protect|-----BEGIN\s+PROTECTED-----|DATA_METHOD\s*=)`),
		Severity: "high",
		MinHits:  1,
	},
	{
		ID:       "us-ssn",
		Name:     "US Social Security Number",
		Category: CategoryPII,
		Pattern:  regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Severity: "medium",
		MinHits:  1,
	},
	{
		ID:       "credit-card-like",
		Name:     "Credit card-like number",
		Category: CategoryPII,
		Pattern:  regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{1,4}\b`),
		Severity: "medium",
		MinHits:  1,
	},
}
