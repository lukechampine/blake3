package guts

import (
	"math/bits"
	"math/rand"
	"testing"
)

// refRoot returns the root node of b, computed serially.
func refRoot(b []byte, key *[8]uint32, counter uint64, flags uint32) Node {
	if len(b) <= ChunkSize {
		return CompressChunk(b, key, counter, flags)
	}
	// the left subtree contains the largest power of two chunks that leaves
	// at least one byte for the right subtree
	chunks := uint64(1) << (bits.Len(uint((len(b)-1)/ChunkSize)) - 1)
	l := ChainingValue(refRoot(b[:chunks*ChunkSize], key, counter, flags))
	r := ChainingValue(refRoot(b[chunks*ChunkSize:], key, counter+chunks, flags))
	return ParentNode(l, r, key, flags)
}

func TestCompressBuffer(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	var buf [MaxSIMD * ChunkSize]byte
	r.Read(buf[:])
	var key [8]uint32
	for i := range key {
		key[i] = r.Uint32()
	}
	for _, counter := range []uint64{0, 1<<32 - 1, 1<<64 - MaxSIMD} {
		for chunks := 0; chunks <= MaxSIMD; chunks++ {
			for _, extra := range []int{-1, 0, 1, ChunkSize / 2} {
				buflen := chunks*ChunkSize + extra
				if buflen < 0 || buflen > len(buf) {
					continue
				}
				got := CompressBuffer(&buf, buflen, &key, counter, FlagKeyedHash)
				exp := refRoot(buf[:buflen], &key, counter, FlagKeyedHash)
				if got != exp {
					t.Fatalf("counter %#x, buflen %v:\ngot  %x\nwant %x", counter, buflen, got, exp)
				}
			}
		}
	}
}

func TestCompressBlocks(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for _, counter := range []uint64{0, 1<<32 - 1, 1<<32 - MaxSIMD/2, 1<<64 - MaxSIMD} {
		n := Node{Counter: counter, BlockLen: uint32(r.Intn(BlockSize + 1)), Flags: uint32(r.Intn(128))}
		for i := range n.CV {
			n.CV[i] = r.Uint32()
		}
		for i := range n.Block {
			n.Block[i] = r.Uint32()
		}
		var got, exp [MaxSIMD * BlockSize]byte
		CompressBlocks(&got, n)
		compressBlocksGeneric(&exp, n)
		if got != exp {
			t.Fatalf("counter %#x:\ngot  %x\nwant %x", counter, got, exp)
		}
	}
}

func TestCompressNode(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for _, counter := range []uint64{0, 1, 1<<32 - 1, 1 << 32, 1<<64 - 1} {
		for range 100 {
			n := Node{Counter: counter, BlockLen: uint32(r.Intn(BlockSize + 1)), Flags: uint32(r.Intn(128))}
			for i := range n.CV {
				n.CV[i] = r.Uint32()
			}
			for i := range n.Block {
				n.Block[i] = r.Uint32()
			}
			if got, exp := CompressNode(n), compressNodeGeneric(&n); got != exp {
				t.Fatalf("counter %#x:\ngot  %x\nwant %x", counter, got, exp)
			}
		}
	}
}

func BenchmarkCompressNode(b *testing.B) {
	n := Node{BlockLen: BlockSize}
	b.SetBytes(BlockSize)
	for i := 0; i < b.N; i++ {
		n.CV = ChainingValue(n)
	}
}

func BenchmarkCompressBuffer(b *testing.B) {
	var buf [MaxSIMD * ChunkSize]byte
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		CompressBuffer(&buf, len(buf), &IV, 0, 0)
	}
}

func BenchmarkCompressBlocks(b *testing.B) {
	var out [MaxSIMD * BlockSize]byte
	b.SetBytes(int64(len(out)))
	for i := 0; i < b.N; i++ {
		CompressBlocks(&out, Node{BlockLen: BlockSize})
	}
}
