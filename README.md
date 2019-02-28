# GmSSL-demo

- [GmSSL-demo](#gmssl-demo)
  - [function](#function)
  - [project](#project)

## function

A demo to test process algorithm with GmSSL, including

- symmetric encryption
  - SM4 block cipher algorithm in ECB mode
- asymmetric encryption
  - SM2 elliptic curve cryptography algorithm
- hash
  - SM3 cryptographic hash algorithm
- random generator

## project

The project is based on qt-creator.

- AlgoProcLib: interface to use GmSSL
- demo: entrance to test above interface
- include: necessary header files
- lib: necessary dynamic library files generated according to [tutorial](http://gmssl.org/docs/install.html)