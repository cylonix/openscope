# NORTHWIND SEMICONDUCTOR — INTERNAL USE ONLY
# Project FALCON — top-level timing constraints (synthetic sample)

current_design falcon_top

create_clock -name core_clk  -period 2.000 [get_ports clk]
create_clock -name jtag_clk  -period 40.00 [get_ports tck]

set_clock_uncertainty 0.080 [get_clocks core_clk]
set_input_delay  0.400 -clock core_clk [all_inputs]
set_output_delay 0.350 -clock core_clk [all_outputs]

set_false_path -from [get_clocks jtag_clk] -to [get_clocks core_clk]
set_multicycle_path 2 -setup -from [get_pins mac/acc_reg*/Q]
set_max_delay 1.800 -from [get_ports data_in*] -to [get_ports data_out*]
