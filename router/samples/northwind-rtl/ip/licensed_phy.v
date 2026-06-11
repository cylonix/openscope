// NORTHWIND SEMICONDUCTOR — third-party licensed IP (DO NOT REDISTRIBUTE)
// Project FALCON — SerDes PHY wrapper, IEEE-1735 encrypted payload.
// Synthetic sample for the OpenScope demo: the pragma markers are real
// IEEE-1735 directives; the encrypted blob is fake.
`timescale 1ns/1ps

`pragma protect begin_protected
`pragma protect version = 1
`pragma protect author = "VendorIP Inc."
`pragma protect encrypt_agent = "ip-encryptor"
`pragma protect data_method = "aes128-cbc"
`pragma protect encoding = (enctype = "base64", line_length = 64, bytes = 512)
`pragma protect DATA_METHOD = "aes128-cbc"
ZmFrZS1lbmNyeXB0ZWQtcGF5bG9hZC1ub3QtcmVhbC1kby1ub3QtdXNlLWluLXByb2Q=
ZmFrZS1lbmNyeXB0ZWQtcGF5bG9hZC1ub3QtcmVhbC1kby1ub3QtdXNlLWluLXByb2Q=
`pragma protect end_protected
