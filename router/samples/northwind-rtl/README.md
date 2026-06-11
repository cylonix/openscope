# northwind-rtl — RESTRICTED

**NORTHWIND SEMICONDUCTOR — COMPANY CONFIDENTIAL**

> Synthetic sample repo for the OpenScope demo. "Northwind Semiconductor" is
> fictional; every file here is hand-written demo content, not a real design.

This repo stands in for a chip company's **crown-jewel IP**: RTL, analog
netlists, timing constraints, licensed third-party IP, the design spec, and
foundry/PDK material. **No external coding agent is permitted to read this
repo.** When an agent is pointed at OpenScope, anything from here is blocked
at the perimeter — the content itself is detected (proprietary HDL, SPICE,
SDC, classification + export markers, secrets), so relabeling the workspace
doesn't smuggle it past the gate.

| Path | What it is | Trips |
|---|---|---|
| `rtl/aes_sbox.sv` | SystemVerilog AES S-box | content-class (Verilog) + classification |
| `rtl/async_fifo.v` | Verilog async FIFO | content-class (Verilog) + classification |
| `analog/bandgap_ref.sp` | SPICE netlist | content-class (SPICE) + classification |
| `constraints/falcon_top.sdc` | Timing constraints | content-class (SDC) + classification |
| `ip/licensed_phy.v` | IEEE-1735 encrypted IP | content-class + secret (encrypted-IP) |
| `docs/design_spec.md` | Microarch spec | classification (CONFIDENTIAL / TRADE SECRET) |
| `docs/export_notice.txt` | Export notice | export-control (ECCN/EAR) + classification |
| `docs/pdk_notes.txt` | PDK notes | foundry-nda (TSMC/N3/PDK) + classification |
| `scripts/run_synth.tcl` | Synthesis flow | secret (AWS key + private key) |

See [`../EXPECTED.md`](../EXPECTED.md) for the full answer key.
