// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"fmt"
	"strings"
)

// RenderText renders a plan as a human report with ASCII tables for fast
// scanning. Every consequence comes from typed fields and the live machine —
// the AI-authored metadata is shown only in a clearly-marked untrusted box.
func RenderText(p Plan) string {
	var b strings.Builder
	pr := p.Proposal

	fmt.Fprintf(&b, "OpenScope plan — %s\n", pr.Metadata.Name)
	fmt.Fprintf(&b, "  source    %s\n", pr.Source)
	fmt.Fprintf(&b, "  sha256    %s\n", pr.SHA256)
	short := pr.SHA256
	if len(short) > 12 {
		short = short[:12]
	}
	fmt.Fprintf(&b, "            pin it:  sudo openscope apply --file %s --expect-hash %s\n", baseName(pr.Source), short)
	daemon := "stopped"
	if p.Machine.DaemonRunning {
		daemon = "running"
	}
	fmt.Fprintf(&b, "  machine   %s @ %s (%s)  ·  daemon: %s\n", p.Machine.User, p.Machine.Host, p.Machine.OS, daemon)
	fmt.Fprintf(&b, "  bounds    %s\n\n", p.BoundsSource)

	// Untrusted metadata box.
	b.WriteString(untrustedBox(pr.Metadata))
	b.WriteString("\n")

	// Changes.
	b.WriteString(section("CHANGES vs live config"))
	c := p.Changes
	sysCell := "no change"
	if c.SystemFirstWrite {
		sysCell = "first write (was empty)"
	}
	b.WriteString(table(
		[]string{"AREA", "CHANGE"},
		[][]string{
			{"ssh targets", fmt.Sprintf("+%d add, -%d remove", c.SSHTargetsAdded, c.SSHTargetsRemoved)},
			{"system allow-lists", fmt.Sprintf("%s — %d mgrs · %d pkgs · %d svcs · %d procs · %d ports",
				sysCell, c.NewManagers, c.NewPackages, c.NewServices, c.NewProcNames, c.NewPorts)},
			{"custom verbs", fmt.Sprintf("+%d defined (command templates)", c.VerbsAdded)},
			{"policy rules", fmt.Sprintf("+%d allow, +%d deny (new vs live)", c.PolicyAllowNew, c.PolicyDenyNew)},
		}, 1, 60))
	b.WriteString("  This proposal only ADDS access; nothing is narrowed or removed.\n\n")

	// Custom verbs: show the EXACT command template + constraints, so the
	// operator confirms what each new verb runs — pinned root-owned at apply.
	if vrows := verbRows(pr); len(vrows) > 0 {
		b.WriteString(section("CUSTOM VERBS ADDED (exact command templates, pinned root-owned at apply)"))
		b.WriteString(table([]string{"APP·ACTION", "COMMAND", "PARAMS"}, vrows, 1, 50))
		b.WriteString("\n")
	}

	// Capabilities.
	b.WriteString(section("WHAT IT WILL BE ABLE TO DO (from typed fields)"))
	capRows := make([][]string, 0, len(p.Capabilities))
	for _, cap := range p.Capabilities {
		capRows = append(capRows, []string{cap.Agent, cap.Action, cap.Scope})
	}
	b.WriteString(table([]string{"AGENT", "APP·ACTION", "SCOPE"}, capRows, 2, 44))
	b.WriteString("\n")

	// Findings.
	blockN, highN, medN, warnN, passN := tally(p)
	b.WriteString(section(fmt.Sprintf("FINDINGS — ⛔ %d blocking · 🔴 %d high · 🟡 %d medium · 🔴 %d warn · ✅ %d pass",
		blockN, highN, medN, warnN, passN)))
	findRows := make([][]string, 0, len(p.Findings))
	for _, f := range p.Findings {
		findRows = append(findRows, []string{sevLabel(p, f), f.RuleID, f.Resource, f.Summary})
	}
	b.WriteString(table([]string{"SEV", "RULE", "RESOURCE", "SUMMARY"}, findRows, 3, 46))
	b.WriteString("\n")
	// Fix hints for blocking findings.
	if len(p.Blocking) > 0 {
		b.WriteString("  Fixes for blocking findings:\n")
		seen := map[string]bool{}
		for _, f := range p.Blocking {
			if f.Fix == "" || seen[f.RuleID+f.Fix] {
				continue
			}
			seen[f.RuleID+f.Fix] = true
			fmt.Fprintf(&b, "    [%s] %s\n", f.RuleID, f.Fix)
		}
		b.WriteString("\n")
	}

	// Bounds.
	b.WriteString(section("BOUNDS (root-owned envelope)"))
	bRows := make([][]string, 0, len(p.BoundsTable))
	for _, r := range p.BoundsTable {
		bRows = append(bRows, []string{r.Name, sevEmoji(r.Status) + " " + r.Status, r.Detail})
	}
	b.WriteString(table([]string{"CHECK", "STATUS", "DETAIL"}, bRows, 0, 44))
	b.WriteString("\n")

	// Verdict.
	b.WriteString(verdict(p))
	return b.String()
}

func verdict(p Plan) string {
	var b strings.Builder
	if p.Blocked {
		fmt.Fprintf(&b, "⛔ VERDICT: BLOCKED — %d bounds violation(s)\n", len(p.Blocking))
		b.WriteString("  apply will refuse. Resolve by editing the proposal per the fixes above,\n")
		b.WriteString("  or deliberately allow by editing bounds.yaml as root (the one explicit place).\n")
	} else if len(p.Acknowledge) > 0 {
		fmt.Fprintf(&b, "🟠 VERDICT: OK with confirmation — %d high finding(s) to acknowledge at apply\n", len(p.Acknowledge))
		b.WriteString("  sudo openscope apply will require typing each flagged resource to confirm.\n")
	} else {
		b.WriteString("✅ VERDICT: clean — no blocking or high findings\n")
		b.WriteString("  sudo openscope apply will write it through the broker's validated paths.\n")
	}
	b.WriteString("  Nothing has been written. plan is read-only and needs no sudo.\n")
	return b.String()
}

// sevEmoji maps a severity/status word to a leading emoji for at-a-glance scan.
// Every glyph is a single code point that renders as 2 terminal columns — we
// avoid ⚠️ (U+26A0 U+FE0F): the variation selector makes its width ambiguous
// across terminals and broke table-column alignment.
func sevEmoji(label string) string {
	switch label {
	case "BLOCK", "FAIL":
		return "⛔"
	case "HIGH":
		return "🔴"
	case "MEDIUM":
		return "🟡"
	case "WARN", "warn":
		return "🔴"
	case "acknowledge":
		return "🟠"
	case "PASS", "pass":
		return "✅"
	}
	return "•"
}

func tally(p Plan) (block, high, med, warn, pass int) {
	blocking := map[string]bool{}
	for _, f := range p.Blocking {
		blocking[f.RuleID+f.Resource] = true
	}
	for _, f := range p.Findings {
		switch {
		case blocking[f.RuleID+f.Resource]:
			block++
		case f.Severity == SevHigh:
			high++
		case f.Severity == SevMedium:
			med++
		case f.Severity == SevWarn:
			warn++
		default:
			pass++
		}
	}
	return
}

func sevLabel(p Plan, f Finding) string {
	label := f.Severity.String()
	if isBlocking(p.Bounds, f) {
		label = "BLOCK"
	}
	return sevEmoji(label) + " " + label
}

func section(title string) string {
	line := strings.Repeat("─", 78)
	return line + "\n" + title + "\n" + line + "\n"
}

func untrustedBox(m Metadata) string {
	var b strings.Builder
	b.WriteString("  ┌─ AI-AUTHORED METADATA — untrusted, NOT used in the review below ─┐\n")
	fmt.Fprintf(&b, "  │ tool %s · model %s · session %s\n", dash(m.AuthoredBy.Tool), dash(m.AuthoredBy.Model), dash(m.AuthoredBy.Session))
	desc := strings.Join(strings.Fields(m.Description), " ")
	for _, line := range wrap(desc, 62) {
		fmt.Fprintf(&b, "  │ %s\n", line)
	}
	b.WriteString("  └──────────────────────────────────────────────────────────────────┘\n")
	return b.String()
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// table renders an ASCII table. wrapCol (>=0) is wrapped to wrapWidth; pass a
// column index out of range to disable wrapping. Column widths and padding use
// display width (emoji count as 2 columns) so emoji cells stay aligned.
func table(headers []string, rows [][]string, wrapCol, wrapWidth int) string {
	cols := len(headers)
	width := make([]int, cols)
	for i, h := range headers {
		width[i] = displayWidth(h)
	}
	// First pass: natural widths (wrap column capped).
	for _, row := range rows {
		for i := 0; i < cols && i < len(row); i++ {
			cell := row[i]
			if i == wrapCol && displayWidth(cell) > wrapWidth {
				width[i] = max(width[i], wrapWidth)
				continue
			}
			width[i] = max(width[i], displayWidth(cell))
		}
	}
	var b strings.Builder
	sep := func() {
		b.WriteString("+")
		for i := 0; i < cols; i++ {
			b.WriteString(strings.Repeat("-", width[i]+2))
			b.WriteString("+")
		}
		b.WriteString("\n")
	}
	writeRow := func(cells []string) {
		// Expand each cell into wrapped lines.
		lines := make([][]string, cols)
		height := 1
		for i := 0; i < cols; i++ {
			val := ""
			if i < len(cells) {
				val = cells[i]
			}
			if i == wrapCol {
				lines[i] = wrap(val, wrapWidth)
			} else {
				lines[i] = []string{val}
			}
			if len(lines[i]) > height {
				height = len(lines[i])
			}
		}
		for h := 0; h < height; h++ {
			b.WriteString("|")
			for i := 0; i < cols; i++ {
				cell := ""
				if h < len(lines[i]) {
					cell = lines[i][h]
				}
				pad := width[i] - displayWidth(cell)
				if pad < 0 {
					pad = 0
				}
				b.WriteString(" ")
				b.WriteString(cell)
				b.WriteString(strings.Repeat(" ", pad))
				b.WriteString(" |")
			}
			b.WriteString("\n")
		}
	}
	sep()
	writeRow(headers)
	sep()
	for _, row := range rows {
		writeRow(row)
	}
	sep()
	return b.String()
}

// displayWidth returns the terminal column count of s, treating emoji and wide
// symbols as 2 columns and variation selectors as 0.
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case r >= 0xFE00 && r <= 0xFE0F: // variation selectors — zero width
		case isWideRune(r):
			w += 2
		default:
			w++
		}
	}
	return w
}

func isWideRune(r rune) bool {
	switch {
	case r >= 0x1F000 && r <= 0x1FAFF: // emoji blocks
		return true
	case r >= 0x2600 && r <= 0x27BF: // misc symbols + dingbats (⛔ ✅ ⚪ ⚠ etc.)
		return true
	case r >= 0x2B00 && r <= 0x2BFF: // misc symbols and arrows
		return true
	case r >= 0x1F1E6 && r <= 0x1F1FF: // regional indicators
		return true
	}
	return false
}

// wrap breaks s into lines no longer than width, on word boundaries.
func wrap(s string, width int) []string {
	if width <= 0 || len(s) <= width {
		return []string{s}
	}
	var lines []string
	var cur string
	for _, word := range strings.Fields(s) {
		switch {
		case cur == "":
			cur = word
		case len(cur)+1+len(word) <= width:
			cur += " " + word
		default:
			lines = append(lines, cur)
			cur = word
		}
		// Hard-break a single word longer than width.
		for len(cur) > width {
			lines = append(lines, cur[:width])
			cur = cur[width:]
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}
