# pyoprf-r255
**WARNING:** This is just a PoC. Use at your own risk.

This is a simple python implementation of the OPRF, VOPRF and POPRF Mode of [RFC 9497](https://datatracker.ietf.org/doc/html/rfc9497) with ciphersuite OPRF(ristretto255, SHA-512). There seems to be a bug in POPRF mode of the RFC (see [here](https://www.rfc-editor.org/errata/eid7999)). This has been taken into account<br /> <br />
It uses [pysodium](https://github.com/stef/pysodium) for all Ristretto255 functions. Therefore it requires a pre-installed libsodium from: <br />
https://github.com/jedisct1/libsodium
## Usage:
tbd