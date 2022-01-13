Create a threshold signature using precomputed nonce shares.

```
go run examples/nonce-sign/main.go -s AoKFEzbu8FyqHBAG7xwkSRA6S3dSmMtZORoK4N0ZFP4Bqgw8XEn8dWPhbIDh2OVm15ycwXbTVtH5Ug2bDJ4IbvE=
==> (1,2)-threshold scheme
 share 1 (t=1): 82851336eef05caa1c1006ef1c2449103a4b775298cb59391a0ae0dd1914fe01

==> Ed25519 signature from 1 signers
 public key (32-byte):	48b0fac23e681df7e22329de448debb2d413f49122944bcce1df8f5a650ef230
 message (12-byte):	Hello World!
 signature (64-byte):	aa0c3c5c49fc7563e16c80e1d8e566d79c9cc176d356d1f9520d9b0c9e086ef1574720930c03c4da48365cc330d2297efcd272c7a79ed36ed733b37bf0a9860a
```
