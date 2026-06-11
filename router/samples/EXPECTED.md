# OpenScope test corpus — expected results (answer key)

This is the **answer key** for the synthetic sample repos. The whole point:
you (or a prospect's security team) never have to upload real confidential IP
to test OpenScope — run this corpus instead and confirm OpenScope's verdicts
match the table below.

- **DENY** = blocked at the perimeter; the content never reaches the model.
- **ALLOW** = forwarded to the model (still audited, still receipted, still
  unreadable by OpenScope operators).

Everything here is 100% synthetic: "Northwind Semiconductor" is fictional, the
AWS key is AWS's own documented example (`AKIAIOSFODNN7EXAMPLE`, non-functional),
and the private-key / encrypted-IP blobs are fake.

## northwind-rtl (RESTRICTED) — all DENY

| File | Expected | Rule IDs that fire |
|---|---|---|
| `rtl/aes_sbox.sv` | **DENY** | `hdl-verilog`, `classification-marker` |
| `rtl/async_fifo.v` | **DENY** | `hdl-verilog`, `classification-marker` |
| `analog/bandgap_ref.sp` | **DENY** | `spice-netlist`, `classification-marker` |
| `constraints/falcon_top.sdc` | **DENY** | `sdc-constraints`, `classification-marker` |
| `ip/licensed_phy.v` | **DENY** | `encrypted-ip-pragma`, `hdl-verilog` |
| `docs/design_spec.md` | **DENY** | `classification-marker` (+ `layout-lef-def-gds` via "GDSII") |
| `docs/export_notice.txt` | **DENY** | `export-control`, `classification-marker` |
| `docs/pdk_notes.txt` | **DENY** | `foundry-pdk`, `classification-marker` |
| `scripts/run_synth.tcl` | **DENY** | `aws-access-key`, `private-key-block` |

## northwind-webapp (ALLOWED) — all ALLOW

| File | Expected | Why |
|---|---|---|
| `src/cart.ts` | **ALLOW** ✅ | ordinary TypeScript, no IP / markers / secrets |
| `src/hello.py` | **ALLOW** ✅ | trivial script |
| `docs/notes.txt` | **ALLOW** ✅ | innocuous meeting notes |

## Detection tiers exercised

- **Tier A — content-class** (the payload *is* proprietary technical artifact):
  `hdl-verilog`, `hdl-vhdl`, `spice-netlist`, `liberty-netlist`,
  `sdc-constraints`, `layout-lef-def-gds`.
- **Tier B — classification + export + foundry**: `classification-marker`,
  `export-control`, `foundry-pdk`.
- **Tier C — secrets + PII**: `aws-access-key`, `private-key-block`,
  `api-token`, `encrypted-ip-pragma`, `us-ssn`, `credit-card-like`.

The "mislabel doesn't help" property: content-class rules are evaluated on the
payload regardless of which workspace claimed to send it — paste `aes_sbox.sv`
into a workspace labeled `northwind-webapp` and it still DENYs on `hdl-verilog`.

> Roadmap (not in this corpus): exact-data-match fingerprinting of registered
> crown-jewel files, so a chunk of *your* specific RTL is caught even with no
> generic signature. That's the production tier.
