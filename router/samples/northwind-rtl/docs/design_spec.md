# Project FALCON — Microarchitecture Specification

**NORTHWIND SEMICONDUCTOR — COMPANY CONFIDENTIAL — TRADE SECRET**
**RESTRICTED DISTRIBUTION — NOT FOR EXTERNAL USE**

> Synthetic sample for the OpenScope demo. Northwind Semiconductor is a
> fictional company; nothing here is a real product or design.

## 1. Overview

FALCON is a 4-wide out-of-order core targeting 3.2 GHz. This document
describes the load/store unit, the AES crypto accelerator, and the SerDes
PHY integration.

## 2. Crypto accelerator

The AES block (`rtl/aes_sbox.sv`) implements a single-cycle S-box bank with
16 parallel lookups per round. Round keys are expanded off the critical path.

## 3. Tapeout target

First silicon targets a leading-edge node (see `docs/pdk_notes.txt`). Mask
data ships as GDSII to the foundry under NDA.
