// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package proposal

import (
	"fmt"
	"html"
	"strings"
)

// RenderHTML renders a plan as a self-contained, styled HTML report (inline
// CSS, no external assets) for `openscope plan --html`. Like the text report,
// every value comes from typed fields — the AI-authored metadata is shown only
// in a clearly-marked untrusted box.
func RenderHTML(p Plan) string {
	pr := p.Proposal
	var b strings.Builder

	verdictClass, verdictText := htmlVerdict(p)

	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	fmt.Fprintf(&b, `<title>OpenScope plan — %s</title>`, esc(pr.Metadata.Name))
	b.WriteString("<style>" + htmlCSS + "</style></head><body><main>")

	// Header.
	fmt.Fprintf(&b, `<header><h1>OpenScope plan <span class="muted">%s</span></h1>`, esc(pr.Metadata.Name))
	daemon := "stopped"
	if p.Machine.DaemonRunning {
		daemon = "running"
	}
	b.WriteString(`<dl class="meta">`)
	kv(&b, "source", pr.Source)
	kv(&b, "sha256", pr.SHA256)
	kv(&b, "machine", fmt.Sprintf("%s @ %s (%s) · daemon: %s", dash(p.Machine.User), p.Machine.Host, p.Machine.OS, daemon))
	kv(&b, "bounds", p.BoundsSource)
	b.WriteString("</dl></header>")

	// Verdict banner (top, so it's the first thing seen).
	fmt.Fprintf(&b, `<div class="verdict %s">%s</div>`, verdictClass, esc(verdictText))

	// Untrusted metadata.
	b.WriteString(`<section class="untrusted"><div class="tag">AI-AUTHORED METADATA — untrusted, not used in the review</div>`)
	fmt.Fprintf(&b, `<p class="mono">tool %s · model %s · session %s</p>`,
		esc(dash(pr.Metadata.AuthoredBy.Tool)), esc(dash(pr.Metadata.AuthoredBy.Model)), esc(dash(pr.Metadata.AuthoredBy.Session)))
	if d := strings.TrimSpace(pr.Metadata.Description); d != "" {
		fmt.Fprintf(&b, `<p class="desc">%s</p>`, esc(d))
	}
	b.WriteString("</section>")

	// Changes.
	c := p.Changes
	sysCell := "no change"
	if c.SystemFirstWrite {
		sysCell = "first write (was empty)"
	}
	b.WriteString(`<h2>Changes vs live config</h2>`)
	htmlTable(&b, []string{"Area", "Change"}, [][]cell{
		{plain("ssh targets"), plain(fmt.Sprintf("+%d add, -%d remove", c.SSHTargetsAdded, c.SSHTargetsRemoved))},
		{plain("system allow-lists"), plain(fmt.Sprintf("%s — %d mgrs · %d pkgs · %d svcs · %d procs · %d ports",
			sysCell, c.NewManagers, c.NewPackages, c.NewServices, c.NewProcNames, c.NewPorts))},
		{plain("policy rules"), plain(fmt.Sprintf("+%d allow, +%d deny (new vs live)", c.PolicyAllowNew, c.PolicyDenyNew))},
	})
	b.WriteString(`<p class="note">This proposal only ADDS access; nothing is narrowed or removed.</p>`)

	// Capabilities.
	b.WriteString(`<h2>What it will be able to do <span class="muted">(from typed fields)</span></h2>`)
	capRows := make([][]cell, 0, len(p.Capabilities))
	for _, cp := range p.Capabilities {
		capRows = append(capRows, []cell{plain(cp.Agent), mono(cp.Action), plain(cp.Scope)})
	}
	htmlTable(&b, []string{"Agent", "App · Action", "Scope"}, capRows)

	// Findings.
	blockN, highN, medN, warnN, passN := tally(p)
	fmt.Fprintf(&b, `<h2>Findings <span class="muted">⛔ %d blocking · 🔴 %d high · 🟡 %d medium · ⚪ %d warn · ✅ %d pass</span></h2>`,
		blockN, highN, medN, warnN, passN)
	findRows := make([][]cell, 0, len(p.Findings))
	for _, f := range p.Findings {
		label := f.Severity.String()
		if isBlocking(p.Bounds, f) {
			label = "BLOCK"
		}
		findRows = append(findRows, []cell{
			{text: sevEmoji(label) + " " + label, class: "sev-" + strings.ToLower(label)},
			mono(f.RuleID), plain(f.Resource), plain(f.Summary),
		})
	}
	htmlTable(&b, []string{"Severity", "Rule", "Resource", "Summary"}, findRows)

	if len(p.Blocking) > 0 {
		b.WriteString(`<h3>Fixes for blocking findings</h3><ul class="fixes">`)
		seen := map[string]bool{}
		for _, f := range p.Blocking {
			if f.Fix == "" || seen[f.RuleID+f.Fix] {
				continue
			}
			seen[f.RuleID+f.Fix] = true
			fmt.Fprintf(&b, `<li><code>%s</code> %s</li>`, esc(f.RuleID), esc(f.Fix))
		}
		b.WriteString("</ul>")
	}

	// Bounds.
	b.WriteString(`<h2>Bounds <span class="muted">(root-owned envelope)</span></h2>`)
	bRows := make([][]cell, 0, len(p.BoundsTable))
	for _, r := range p.BoundsTable {
		bRows = append(bRows, []cell{
			mono(r.Name),
			{text: sevEmoji(r.Status) + " " + r.Status, class: "status-" + strings.ToLower(r.Status)},
			plain(r.Detail),
		})
	}
	htmlTable(&b, []string{"Check", "Status", "Detail"}, bRows)

	b.WriteString(`<footer>Nothing has been written. plan is read-only and needs no sudo.</footer>`)
	b.WriteString("</main></body></html>")
	return b.String()
}

func htmlVerdict(p Plan) (class, text string) {
	switch {
	case p.Blocked:
		return "blocked", fmt.Sprintf("⛔ BLOCKED — %d bounds violation(s). apply will refuse until resolved.", len(p.Blocking))
	case len(p.Acknowledge) > 0:
		return "ack", fmt.Sprintf("⚠️ OK with confirmation — %d high finding(s) to acknowledge at apply.", len(p.Acknowledge))
	default:
		return "clean", "✅ Clean — no blocking or high findings."
	}
}

type cell struct {
	text  string
	class string
	mono  bool
}

func plain(s string) cell { return cell{text: s} }
func mono(s string) cell  { return cell{text: s, mono: true} }

func htmlTable(b *strings.Builder, headers []string, rows [][]cell) {
	b.WriteString(`<table><thead><tr>`)
	for _, h := range headers {
		fmt.Fprintf(b, `<th>%s</th>`, esc(h))
	}
	b.WriteString(`</tr></thead><tbody>`)
	for _, row := range rows {
		b.WriteString("<tr>")
		for _, c := range row {
			class := c.class
			if c.mono {
				class = strings.TrimSpace(class + " mono")
			}
			if class != "" {
				fmt.Fprintf(b, `<td class="%s">%s</td>`, class, esc(c.text))
			} else {
				fmt.Fprintf(b, `<td>%s</td>`, esc(c.text))
			}
		}
		b.WriteString("</tr>")
	}
	b.WriteString(`</tbody></table>`)
}

func kv(b *strings.Builder, k, v string) {
	fmt.Fprintf(b, `<dt>%s</dt><dd class="mono">%s</dd>`, esc(k), esc(v))
}

func esc(s string) string { return html.EscapeString(s) }

const htmlCSS = `
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#e6edf3;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 24px 64px}
h1{font-size:24px;margin:0 0 12px}
h2{font-size:18px;margin:32px 0 12px;border-bottom:1px solid #21262d;padding-bottom:6px}
h3{font-size:15px;margin:20px 0 8px;color:#9da7b3}
.muted{color:#7d8590;font-weight:400}
.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px;margin:0}
dl.meta dt{color:#7d8590}
dl.meta dd{margin:0;word-break:break-all}
.verdict{margin:20px 0;padding:14px 18px;border-radius:8px;font-weight:600;font-size:16px}
.verdict.blocked{background:#3d1418;border:1px solid #f85149;color:#ffb4ab}
.verdict.ack{background:#3a2c0a;border:1px solid #d29922;color:#f2cc60}
.verdict.clean{background:#0f2d1a;border:1px solid #3fb950;color:#7ee787}
.untrusted{margin:16px 0;padding:12px 16px;border:1px dashed #484f58;border-radius:8px;background:#161b22}
.untrusted .tag{font-size:12px;letter-spacing:.04em;color:#7d8590;margin-bottom:6px}
.untrusted .desc{color:#9da7b3;margin:6px 0 0}
.note{color:#7d8590;font-size:13px;margin:8px 0 0}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:14px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #21262d;vertical-align:top}
th{color:#7d8590;font-weight:600;font-size:12px;letter-spacing:.03em;text-transform:uppercase}
tbody tr:hover{background:#161b22}
td.sev-block{color:#ffb4ab;font-weight:600;white-space:nowrap}
td.sev-high{color:#ff9492;font-weight:600;white-space:nowrap}
td.sev-medium{color:#e3b341;white-space:nowrap}
td.sev-warn{color:#9da7b3;white-space:nowrap}
td.sev-pass{color:#7ee787;white-space:nowrap}
td.status-fail{color:#ffb4ab;font-weight:600}
td.status-pass{color:#7ee787}
td.status-acknowledge{color:#f2cc60}
ul.fixes{margin:6px 0;padding-left:20px;color:#c9d1d9}
ul.fixes code{color:#ffb4ab}
footer{margin-top:32px;color:#7d8590;font-size:13px;border-top:1px solid #21262d;padding-top:12px}
`
