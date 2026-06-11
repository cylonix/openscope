* NORTHWIND SEMICONDUCTOR — COMPANY CONFIDENTIAL
* Project FALCON — bandgap voltage reference (synthetic sample)
* Device models below are placeholders, NOT a real PDK.

.subckt bandgap_ref vref vdd vss
  q1 n1 n1 vss pnp_unit area=1
  q2 n2 n2 vss pnp_unit area=8
  r1 vref n1 12k
  r2 vref n2 12k
  r3 n2 vss 2.4k
  xop n1 n2 vref vdd vss opamp
.ends bandgap_ref

.model pnp_unit pnp (is=1e-16 bf=100 vaf=50)

.subckt opamp inp inn out vdd vss
  m1 out inn n3 vss nmos_054 w=4u l=0.18u
  m2 n4 inp n3 vss nmos_054 w=4u l=0.18u
.ends opamp

.model nmos_054 nmos (level=54 vth0=0.42 tox=4.1e-9)

.param temp=27
.tran 1n 200n
.end
