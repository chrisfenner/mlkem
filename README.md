# mlkem
Go bindings to https://github.com/pq-code-package/mlkem-native

This project vendors https://github.com/pq-code-package/mlkem-native, whose
[license](https://github.com/pq-code-package/mlkem-native?tab=License-1-ov-file#readme)
is a combination of Apache 2.0, ISC, and MIT. This project's [license](LICENSE)
is regular Apache 2.0.

## Purpose

This package is intended for R&D and testing purposes only. Users looking for a
production-ready implementation of ML-KEM should use
[crypto/mlkem](https://pkg.go.dev/crypto/mlkem). Users looking for an easy way
to get started experimenting with ML-KEM and creating test vectors for their
protocols have come to the right place.

All three parameter sets of ML-KEM (ML-KEM-512, ML-KEM-768, ML-KEM-1024) are
supported. Randomness is sourced as-needed by a caller-provided `io.Reader`.
Derandomized keygen and encapsulation can be achieved using `bytes.NewReader`:

```go
sk, err := MLKEM768.GenerateKeypair(bytes.NewReader(seed))
ss, ct, err := sk.PublicKey().Encapsulate(bytes.NewReader(randomness))
```

## Getting Started

```sh
go get github.com/chrisfenner/mlkem
```

This package vendors https://github.com/pq-code-package/mlkem-native and
wraps it with cgo. [mlkem.go](mlkem.go) contains the main package API.
