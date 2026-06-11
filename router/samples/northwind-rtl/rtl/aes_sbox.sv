// NORTHWIND SEMICONDUCTOR — COMPANY CONFIDENTIAL
// Project FALCON — AES-128 substitution box (combinational ROM)
// Synthetic sample for the OpenScope demo. Not a real product.
`timescale 1ns/1ps

module aes_sbox (
    input  wire [7:0] in_byte,
    output reg  [7:0] out_byte
);
  // Rijndael S-box lookup. Values are the public AES standard table.
  always_comb begin
    case (in_byte)
      8'h00: out_byte = 8'h63;
      8'h01: out_byte = 8'h7c;
      8'h02: out_byte = 8'h77;
      8'h53: out_byte = 8'hed;
      8'hff: out_byte = 8'h16;
      default: out_byte = 8'h00;
    endcase
  end
endmodule

module aes_round (
    input  wire        clk,
    input  wire        rst_n,
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output reg  [127:0] state_out
);
  wire [127:0] subbed;
  genvar i;
  generate
    for (i = 0; i < 16; i = i + 1) begin : sbox_bank
      aes_sbox u_sbox (.in_byte(state_in[i*8 +: 8]), .out_byte(subbed[i*8 +: 8]));
    end
  endgenerate

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) state_out <= 128'd0;
    else        state_out <= subbed ^ round_key;
  end
endmodule
