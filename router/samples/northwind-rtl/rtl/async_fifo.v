// NORTHWIND SEMICONDUCTOR — PROPRIETARY AND CONFIDENTIAL
// Project FALCON — asynchronous FIFO with gray-code pointers
// Synthetic sample for the OpenScope demo.
`timescale 1ns/1ps

module async_fifo #(
    parameter WIDTH = 32,
    parameter DEPTH = 16,
    parameter AW    = 4
) (
    input  wire            wclk,
    input  wire            wrst_n,
    input  wire            winc,
    input  wire [WIDTH-1:0] wdata,
    output reg             wfull,

    input  wire            rclk,
    input  wire            rrst_n,
    input  wire            rinc,
    output reg  [WIDTH-1:0] rdata,
    output reg             rempty
);
  reg [WIDTH-1:0] mem [0:DEPTH-1];
  reg [AW:0] wptr, rptr;
  wire [AW:0] wgray = (wptr >> 1) ^ wptr;

  always @(posedge wclk or negedge wrst_n) begin
    if (!wrst_n) wptr <= 0;
    else if (winc && !wfull) begin
      mem[wptr[AW-1:0]] <= wdata;
      wptr <= wptr + 1'b1;
    end
  end

  always @(posedge rclk or negedge rrst_n) begin
    if (!rrst_n) rptr <= 0;
    else if (rinc && !rempty) begin
      rdata <= mem[rptr[AW-1:0]];
      rptr <= rptr + 1'b1;
    end
  end

  assign wfull  = (wgray == {~rptr[AW:AW-1], rptr[AW-2:0]});
endmodule
