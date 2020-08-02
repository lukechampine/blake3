blake3
------

[![GoDoc](https://godoc.org/lukechampine.com/blake3?status.svg)](https://godoc.org/lukechampine.com/blake3)
[![Go Report Card](http://goreportcard.com/badge/lukechampine.com/blake3)](https://goreportcard.com/report/lukechampine.com/blake3)

```
go get lukechampine.com/blake3
```

`blake3` implements the [BLAKE3 cryptographic hash function](https://github.com/BLAKE3-team/BLAKE3).
This implementation aims to be performant without sacrificing (too much)
readability, in the hopes of eventually landing in `x/crypto`.

The pure-Go code is fairly well-optimized, achieving throughput of ~600 MB/s.
There is a separate code path for small inputs (up to 64 bytes) that runs in
~100 ns. On CPUs with AVX2 support, larger inputs (>=2 KB) are handled by
an [`avo`](https://github.com/mmcloughlin/avo)-generated assembly routine that compresses 8 nodes in parallel,
achieving throughput of ~2600 MB/s. AVX2 is also used for BLAKE3's extendable output function,
enabling it to stream pseudorandom bytes at ~3500 MB/s. Once [AVX-512 support](https://github.com/mmcloughlin/avo/issues/20) is added to `avo`, it
will be possible to compress 16 nodes in parallel, which should roughly double
the current performance.

Contributions are greatly appreciated.
[All contributors are eligible to receive an Urbit planet.](https://twitter.com/lukechampine/status/1274797924522885134)


## Benchmarks

Tested on an i5-7600K @ 3.80GHz.

```
BenchmarkSum256/64           105 ns/op       609.51 MB/s
BenchmarkSum256/1024        1778 ns/op       576.00 MB/s
BenchmarkSum256/65536      24785 ns/op      2644.15 MB/s
BenchmarkWrite               389 ns/op      2631.78 MB/s
BenchmarkXOF                 293 ns/op      3492.94 MB/s
```
