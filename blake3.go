// Package blake3 implements the BLAKE3 cryptographic hash function.
package blake3

import (
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math"
	"math/bits"
)

const (
	blockSize = 64
	chunkSize = 1024
)

// flags
const (
	flagChunkStart = 1 << iota
	flagChunkEnd
	flagParent
	flagRoot
	flagKeyedHash
	flagDeriveKeyContext
	flagDeriveKeyMaterial
)

var iv = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

// helper functions for converting between bytes and BLAKE3 "words"

func bytesToWords(bytes []byte, words []uint32) {
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(bytes[i*4:])
	}
}

func wordsToBytes(words []uint32, bytes []byte) {
	for i, w := range words {
		binary.LittleEndian.PutUint32(bytes[i*4:], w)
	}
}

func g(a, b, c, d, mx, my uint32) (uint32, uint32, uint32, uint32) {
	a += b + mx
	d = bits.RotateLeft32(d^a, -16)
	c += d
	b = bits.RotateLeft32(b^c, -12)
	a += b + my
	d = bits.RotateLeft32(d^a, -8)
	c += d
	b = bits.RotateLeft32(b^c, -7)
	return a, b, c, d
}

// A node represents a chunk or parent in the BLAKE3 Merkle tree. In BLAKE3
// terminology, the elements of the bottom layer (aka "leaves") of the tree are
// called chunk nodes, and the elements of upper layers (aka "interior nodes")
// are called parent nodes.
//
// Computing a BLAKE3 hash involves splitting the input into chunk nodes, then
// repeatedly merging these nodes into parent nodes, until only a single "root"
// node remains. The root node can then be used to generate up to 2^64 - 1 bytes
// of pseudorandom output.
type node struct {
	// the chaining value from the previous state
	cv [8]uint32
	// the current state
	block    [16]uint32
	counter  uint64
	blockLen uint32
	flags    uint32
}

// compress is the core hash function, generating 16 pseudorandom words from a
// node. When nodes are being merged into parents, only the first 8 words are
// used. When the root node is being used to generate output, the full 16 words
// are used.
func (n node) compress() [16]uint32 {
	// round1 rather than init s and mix, do both.
	// mix the columns.
	s0, s4, s8, s12 := g(n.cv[0], n.cv[4], iv[0], uint32(n.counter), n.block[0], n.block[1])
	s1, s5, s9, s13 := g(n.cv[1], n.cv[5], iv[1], uint32(n.counter>>32), n.block[2], n.block[3])
	s2, s6, s10, s14 := g(n.cv[2], n.cv[6], iv[2], n.blockLen, n.block[4], n.block[5])
	s3, s7, s11, s15 := g(n.cv[3], n.cv[7], iv[3], n.flags, n.block[6], n.block[7])

	// Mix the diagonals.
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[8], n.block[9])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[10], n.block[11])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[12], n.block[13])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[14], n.block[15])
	// round2

	// Mix the columns.
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[2], n.block[6])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[3], n.block[10])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[7], n.block[0])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[4], n.block[13])

	// Mix the diagonals.
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[1], n.block[11])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[12], n.block[5])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[9], n.block[14])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[15], n.block[8])
	// round3

	// Mix the columns.
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[3], n.block[4])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[10], n.block[12])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[13], n.block[2])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[7], n.block[14])

	// Mix the diagonals.
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[6], n.block[5])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[9], n.block[0])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[11], n.block[15])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[8], n.block[1])
	// round4

	// Mix the columns.
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[10], n.block[7])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[12], n.block[9])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[14], n.block[3])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[13], n.block[15])

	// Mix the diagonals.
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[4], n.block[0])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[11], n.block[2])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[5], n.block[8])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[1], n.block[6])
	// round5

	// Mix the columns.
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[12], n.block[13])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[9], n.block[11])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[15], n.block[10])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[14], n.block[8])

	// Mix the diagonals.
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[7], n.block[2])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[5], n.block[3])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[0], n.block[1])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[6], n.block[4])
	// round6

	// Mix the columns.
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[9], n.block[14])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[11], n.block[5])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[8], n.block[12])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[15], n.block[1])

	// Mix the diagonals.
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[13], n.block[3])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[0], n.block[10])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[2], n.block[6])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[4], n.block[7])
	// round7

	// Mix the columns.
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[11], n.block[15])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[5], n.block[0])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[1], n.block[9])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[8], n.block[6])

	// Mix the diagonals.
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[14], n.block[10])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[2], n.block[12])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[3], n.block[4])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[7], n.block[13])

	return [16]uint32{
		s0 ^ s8, s1 ^ s9, s2 ^ s10, s3 ^ s11,
		s4 ^ s12, s5 ^ s13, s6 ^ s14, s7 ^ s15,
		s8 ^ n.cv[0], s9 ^ n.cv[1], s10 ^ n.cv[2], s11 ^ n.cv[3],
		s12 ^ n.cv[4], s13 ^ n.cv[5], s14 ^ n.cv[6], s15 ^ n.cv[7],
	}
}

// chainingValue returns the first 8 words of the compressed node. This is used
// in two places. First, when a chunk node is being constructed, its cv is
// overwritten with this value after each block of input is processed. Second,
// when two nodes are merged into a parent, each of their chaining values
// supplies half of the new node's block. Second, when
func (n node) chainingValue() (cv [8]uint32) {
	full := n.compress()
	copy(cv[:], full[:8])
	return
}

// chunkState manages the state involved in hashing a single chunk of input.
type chunkState struct {
	n             node
	block         [blockSize]byte
	blockLen      int
	bytesConsumed int
}

// chunkCounter is the index of this chunk, i.e. the number of chunks that have
// been processed prior to this one.
func (cs *chunkState) chunkCounter() uint64 {
	return cs.n.counter
}

func (cs *chunkState) complete() bool {
	return cs.bytesConsumed == chunkSize
}

// update incorporates input into the chunkState.
func (cs *chunkState) update(input []byte) {
	for len(input) > 0 {
		// If the block buffer is full, compress it and clear it. More
		// input is coming, so this compression is not flagChunkEnd.
		if cs.blockLen == blockSize {
			// copy the chunk block (bytes) into the node block and chain it.
			bytesToWords(cs.block[:], cs.n.block[:])
			cs.n.cv = cs.n.chainingValue()
			// clear the start flag for all but the first block
			cs.n.flags &^= flagChunkStart
			cs.blockLen = 0
		}

		// Copy input bytes into the chunk block.
		n := copy(cs.block[cs.blockLen:], input)
		cs.blockLen += n
		cs.bytesConsumed += n
		input = input[n:]
	}
}

// compiles to memclr
func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// node returns a node containing the chunkState's current state, with the
// ChunkEnd flag set.
func (cs *chunkState) node() node {
	n := cs.n
	// pad the remaining space in the block with zeros
	clear(cs.block[cs.blockLen:])
	bytesToWords(cs.block[:], n.block[:])
	n.blockLen = uint32(cs.blockLen)
	n.flags |= flagChunkEnd
	return n
}

func newChunkState(iv [8]uint32, chunkCounter uint64, flags uint32) chunkState {
	return chunkState{
		n: node{
			cv:       iv,
			counter:  chunkCounter,
			blockLen: blockSize,
			// compress the first block with the start flag set
			flags: flags | flagChunkStart,
		},
	}
}

// parentNode returns a node that incorporates the chaining values of two child
// nodes.
func parentNode(left, right [8]uint32, key [8]uint32, flags uint32) node {
	var blockWords [16]uint32
	copy(blockWords[:8], left[:])
	copy(blockWords[8:], right[:])
	return node{
		cv:       key,
		block:    blockWords,
		counter:  0,         // counter is reset for parents
		blockLen: blockSize, // block is full: 8 words from left, 8 from right
		flags:    flags | flagParent,
	}
}

// Hasher implements hash.Hash.
type Hasher struct {
	cs    chunkState
	key   [8]uint32
	flags uint32
	size  int // output size, for Sum

	// log(n) set of Merkle subtree roots, at most one per height.
	stack [54][8]uint32 // 2^54 * chunkSize = 2^64
	used  uint64        // bit vector indicating which stack elems are valid; also number of chunks added
}

func (h *Hasher) hasSubtreeAtHeight(i uint64) bool {
	return h.used&(1<<i) != 0
}

// addChunkChainingValue appends a chunk to the right edge of the Merkle tree.
func (h *Hasher) addChunkChainingValue(cv [8]uint32) {
	// seek to first open stack slot, merging subtrees as we go
	i := uint64(0)
	for ; h.hasSubtreeAtHeight(i); i++ {
		cv = parentNode(h.stack[i], cv, h.key, h.flags).chainingValue()
	}
	h.stack[i] = cv
	h.used++
}

// rootNode computes the root of the Merkle tree. It does not modify the
// chainStack.
func (h *Hasher) rootNode() node {
	n := h.cs.node()
	for i := uint64(bits.TrailingZeros64(h.used)); i < 64; i++ {
		if h.hasSubtreeAtHeight(i) {
			n = parentNode(h.stack[i], n.chainingValue(), h.key, h.flags)
		}
	}
	n.flags |= flagRoot
	return n
}

// Reset implements hash.Hash.
func (h *Hasher) Reset() {
	h.cs = newChunkState(h.key, 0, h.flags)
	h.used = 0
}

// BlockSize implements hash.Hash.
func (h *Hasher) BlockSize() int { return 64 }

// Size implements hash.Hash.
func (h *Hasher) Size() int { return h.size }

// Write implements hash.Hash.
func (h *Hasher) Write(p []byte) (int, error) {
	lenp := len(p)
	for len(p) > 0 {
		// If the current chunk is complete, finalize it and add it to the tree,
		// then reset the chunk state (but keep incrementing the counter across
		// chunks).
		if h.cs.complete() {
			cv := h.cs.node().chainingValue()
			h.addChunkChainingValue(cv)
			h.cs = newChunkState(h.key, h.cs.chunkCounter()+1, h.flags)
		}

		// Compress input bytes into the current chunk state.
		n := chunkSize - h.cs.bytesConsumed
		if n > len(p) {
			n = len(p)
		}
		h.cs.update(p[:n])
		p = p[n:]
	}
	return lenp, nil
}

// Sum implements hash.Hash.
func (h *Hasher) Sum(b []byte) (sum []byte) {
	// We need to append h.Size() bytes to b. Reuse b's capacity if possible;
	// otherwise, allocate a new slice.
	if total := len(b) + h.Size(); cap(b) >= total {
		sum = b[:total]
	} else {
		sum = make([]byte, total)
		copy(sum, b)
	}
	// Read into the appended portion of sum
	h.XOF().Read(sum[len(b):])
	return
}

// XOF returns an OutputReader initialized with the current hash state.
func (h *Hasher) XOF() *OutputReader {
	return &OutputReader{
		n: h.rootNode(),
	}
}

func newHasher(key [8]uint32, flags uint32, size int) *Hasher {
	return &Hasher{
		cs:    newChunkState(key, 0, flags),
		key:   key,
		flags: flags,
		size:  size,
	}
}

// New returns a Hasher for the specified size and key. If key is nil, the hash
// is unkeyed.
func New(size int, key []byte) *Hasher {
	if key == nil {
		return newHasher(iv, 0, size)
	}
	var keyWords [8]uint32
	bytesToWords(key[:], keyWords[:])
	return newHasher(keyWords, flagKeyedHash, size)
}

// Sum256 returns the unkeyed BLAKE3 hash of b, truncated to 256 bits.
func Sum256(b []byte) (out [32]byte) {
	h := newHasher(iv, 0, 0)
	h.Write(b)
	h.XOF().Read(out[:])
	return
}

// Sum512 returns the unkeyed BLAKE3 hash of b, truncated to 512 bits.
func Sum512(b []byte) (out [64]byte) {
	h := newHasher(iv, 0, 0)
	h.Write(b)
	h.XOF().Read(out[:])
	return
}

// DeriveKey derives a subkey from ctx and srcKey. ctx should be hardcoded,
// globally unique, and application-specific. A good format for ctx strings is:
//
//    [application] [commit timestamp] [purpose]
//
// e.g.:
//
//    example.com 2019-12-25 16:18:03 session tokens v1
//
// The purpose of these requirements is to ensure that an attacker cannot trick
// two different applications into using the same context string.
func DeriveKey(subKey []byte, ctx string, srcKey []byte) {
	// construct the derivation Hasher
	const derivationIVLen = 32
	h := newHasher(iv, flagDeriveKeyContext, 32)
	h.Write([]byte(ctx))
	var derivationIV [8]uint32
	bytesToWords(h.Sum(make([]byte, 0, derivationIVLen)), derivationIV[:])
	h = newHasher(derivationIV, flagDeriveKeyMaterial, 0)
	// derive the subKey
	h.Write(srcKey)
	h.XOF().Read(subKey)
}

// An OutputReader produces an seekable stream of 2^64 - 1 pseudorandom output
// bytes.
type OutputReader struct {
	n     node
	block [blockSize]byte
	off   uint64
}

// Read implements io.Reader. Callers may assume that Read returns len(p), nil
// unless the read would extend beyond the end of the stream.
func (or *OutputReader) Read(p []byte) (int, error) {
	if or.off == math.MaxUint64 {
		return 0, io.EOF
	} else if rem := math.MaxUint64 - or.off; uint64(len(p)) > rem {
		p = p[:rem]
	}
	lenp := len(p)
	for len(p) > 0 {
		if or.off%blockSize == 0 {
			or.n.counter = or.off / blockSize
			words := or.n.compress()
			wordsToBytes(words[:], or.block[:])
		}

		n := copy(p, or.block[or.off%blockSize:])
		p = p[n:]
		or.off += uint64(n)
	}
	return lenp, nil
}

// Seek implements io.Seeker.
func (or *OutputReader) Seek(offset int64, whence int) (int64, error) {
	off := or.off
	switch whence {
	case io.SeekStart:
		if offset < 0 {
			return 0, errors.New("seek position cannot be negative")
		}
		off = uint64(offset)
	case io.SeekCurrent:
		if offset < 0 {
			if uint64(-offset) > off {
				return 0, errors.New("seek position cannot be negative")
			}
			off -= uint64(-offset)
		} else {
			off += uint64(offset)
		}
	case io.SeekEnd:
		off = uint64(offset) - 1
	default:
		panic("invalid whence")
	}
	or.off = off
	or.n.counter = uint64(off) / blockSize
	if or.off%blockSize != 0 {
		words := or.n.compress()
		wordsToBytes(words[:], or.block[:])
	}
	// NOTE: or.off >= 2^63 will result in a negative return value.
	// Nothing we can do about this.
	return int64(or.off), nil
}

// ensure that Hasher implements hash.Hash
var _ hash.Hash = (*Hasher)(nil)
