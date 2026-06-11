#!/usr/bin/env tclsh
# NORTHWIND SEMICONDUCTOR — INTERNAL USE ONLY
# Project FALCON — synthesis + artifact upload flow (synthetic sample).
#
# NOTE: the credentials below are FAKE placeholders for the OpenScope demo.
#   - AKIAIOSFODNN7EXAMPLE is AWS's own documented example key (non-functional)
#   - the private key block is not a real key
# They exist so the DLP scanner has something to catch.

set top_module   "falcon_top"
set target_lib   "nw_sc3_12track"

# --- Synthesis ---------------------------------------------------------------
read_verilog ../rtl/aes_sbox.sv ../rtl/async_fifo.v
read_sdc     ../constraints/falcon_top.sdc
compile_ultra -gate_clock

# --- Push netlist to the build bucket (FAKE creds) ---------------------------
set aws_access_key_id     "AKIAIOSFODNN7EXAMPLE"
set aws_secret_access_key "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE"

set deploy_key "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAfake0000fake0000fake0000fake0000fake0000fake0000
not-a-real-key-do-not-use-this-is-a-demo-fixture-only-0000000000
-----END RSA PRIVATE KEY-----"

exec aws s3 cp falcon_top.netlist.v s3://northwind-builds/falcon/
