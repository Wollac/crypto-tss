Create and encode secrets using a (t,n)-threshold scheme.

```
go run examples/keygen/main.go -t 1 -n 2
==> Generate 1 shared secrets in a (1,2)-threshold scheme
  secret 0: 82851336eef05caa1c1006ef1c2449103a4b775298cb59391a0ae0dd1914fe01
    share 00 (65-byte): AIKFEzbu8FyqHBAG7xwkSRA6S3dSmMtZORoK4N0ZFP4Bqgw8XEn8dWPhbIDh2OVm15ycwXbTVtH5Ug2bDJ4IbvE=
    share 01 (65-byte): AoKFEzbu8FyqHBAG7xwkSRA6S3dSmMtZORoK4N0ZFP4Bqgw8XEn8dWPhbIDh2OVm15ycwXbTVtH5Ug2bDJ4IbvE=

==> Stored 2 shares in 'shares.json'
```
