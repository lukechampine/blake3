blake3
------

[![GoDoc](https://godoc.org/lukechampine.com/blake3?status.svg)](https://godoc.org/lukechampine.com/blake3)
[![Go Report Card](http://goreportcard.com/badge/lukechampine.com/blake3)](https://goreportcard.com/report/lukechampine.com/blake3)

```
go get lukechampine.com/blake3
```

`blake3` implements the [BLAKE3 cryptographic hash function](https://github.com/BLAKE3-team/BLAKE3).

This implementation is a direct port of the Rust reference implementation. It
has not been optimized for performance, and is not written in idiomatic Go
style. I may clean it up later and optimize it to some degree, but don't expect
good performance until someone writes an assembly version.
