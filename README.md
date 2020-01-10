blake3
------

[![GoDoc](https://godoc.org/lukechampine.com/blake3?status.svg)](https://godoc.org/lukechampine.com/blake3)
[![Go Report Card](http://goreportcard.com/badge/lukechampine.com/blake3)](https://goreportcard.com/report/lukechampine.com/blake3)

```
go get lukechampine.com/blake3
```

`blake3` implements the [BLAKE3 cryptographic hash function](https://github.com/BLAKE3-team/BLAKE3).

This implementation is a port of the Rust reference implementation, refactored
into more idiomatic Go style and with a handful of performance tweaks.
Performance is not great, not terrible. Eventually an assembly-optimized
implementation will be merged into `x/crypto`, and then you should switch to
that. In the meantime, you can use this package for code that needs BLAKE3
compatibility and doesn't need to be blazing fast.
