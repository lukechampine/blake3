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

// The g function, split into two parts so that the compiler will inline it.
func gx(state *[16]uint32, a, b, c, d int, mx uint32) {
	state[a] += state[b] + mx
	state[d] = bits.RotateLeft32(state[d]^state[a], -16)
	state[c] += state[d]
	state[b] = bits.RotateLeft32(state[b]^state[c], -12)
}

func gy(state *[16]uint32, a, b, c, d int, my uint32) {
	state[a] += state[b] + my
	state[d] = bits.RotateLeft32(state[d]^state[a], -8)
	state[c] += state[d]
	state[b] = bits.RotateLeft32(state[b]^state[c], -7)
}

func round(state *[16]uint32, m *[16]uint32) {
	// Mix the columns.
	gx(state, 0, 4, 8, 12, m[0])
	gy(state, 0, 4, 8, 12, m[1])
	gx(state, 1, 5, 9, 13, m[2])
	gy(state, 1, 5, 9, 13, m[3])
	gx(state, 2, 6, 10, 14, m[4])
	gy(state, 2, 6, 10, 14, m[5])
	gx(state, 3, 7, 11, 15, m[6])
	gy(state, 3, 7, 11, 15, m[7])

	// Mix the diagonals.
	gx(state, 0, 5, 10, 15, m[8])
	gy(state, 0, 5, 10, 15, m[9])
	gx(state, 1, 6, 11, 12, m[10])
	gy(state, 1, 6, 11, 12, m[11])
	gx(state, 2, 7, 8, 13, m[12])
	gy(state, 2, 7, 8, 13, m[13])
	gx(state, 3, 4, 9, 14, m[14])
	gy(state, 3, 4, 9, 14, m[15])
}

func permute(m *[16]uint32) {
	*m = [16]uint32{
		m[2], m[6], m[3], m[10],
		m[7], m[0], m[4], m[13],
		m[1], m[11], m[12], m[5],
		m[9], m[14], m[15], m[8],
	}
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
	state := [16]uint32{
		n.cv[0], n.cv[1], n.cv[2], n.cv[3],
		n.cv[4], n.cv[5], n.cv[6], n.cv[7],
		iv[0], iv[1], iv[2], iv[3],
		uint32(n.counter), uint32(n.counter >> 32), n.blockLen, n.flags,
	}

	round(&state, &n.block) // round 1
	permute(&n.block)
	round(&state, &n.block) // round 2
	permute(&n.block)
	round(&state, &n.block) // round 3
	permute(&n.block)
	round(&state, &n.block) // round 4
	permute(&n.block)
	round(&state, &n.block) // round 5
	permute(&n.block)
	round(&state, &n.block) // round 6
	permute(&n.block)
	round(&state, &n.block) // round 7

	for i := range n.cv {
		state[i] ^= state[i+8]
		state[i+8] ^= n.cv[i]
	}
	return state
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
			// reset the chunk block. It must contain zeros, because BLAKE3
			// blocks are zero-padded.
			cs.block = [blockSize]byte{}
			cs.blockLen = 0
		}

		// Copy input bytes into the chunk block.
		n := copy(cs.block[cs.blockLen:], input)
		cs.blockLen += n
		cs.bytesConsumed += n
		input = input[n:]
	}
}

// node returns a node containing the chunkState's current state, with the
// ChunkEnd flag set.
func (cs *chunkState) node() node {
	n := cs.n
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
	cs         chunkState
	key        [8]uint32
	chainStack [54][8]uint32 // space for 54 subtrees (2^54 * chunkSize = 2^64)
	stackSize  int           // number of chainStack elements that are valid
	flags      uint32
	size       int // output size, for Sum
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

// addChunkChainingValue appends a chunk to the right edge of the Merkle tree.
func (h *Hasher) addChunkChainingValue(cv [8]uint32, totalChunks uint64) {
	// This chunk might complete some subtrees. For each completed subtree, its
	// left child will be the current top entry in the CV stack, and its right
	// child will be the current value of cv. Pop each left child off the stack,
	// merge it with cv, and overwrite cv with the result. After all these
	// merges, push the final value of cv onto the stack. The number of
	// completed subtrees is given by the number of trailing 0-bits in the new
	// total number of chunks.
	for totalChunks&1 == 0 {
		// pop and merge
		h.stackSize--
		cv = parentNode(h.chainStack[h.stackSize], cv, h.key, h.flags).chainingValue()
		totalChunks >>= 1
	}
	h.chainStack[h.stackSize] = cv
	h.stackSize++
}

// rootNode computes the root of the Merkle tree. It does not modify the
// chainStack.
func (h *Hasher) rootNode() node {
	// Starting with the node from the current chunk, compute all the
	// parent chaining values along the right edge of the tree, until we
	// have the root node.
	n := h.cs.node()
	for i := h.stackSize - 1; i >= 0; i-- {
		n = parentNode(h.chainStack[i], n.chainingValue(), h.key, h.flags)
	}
	n.flags |= flagRoot
	return n
}

// Reset implements hash.Hash.
func (h *Hasher) Reset() {
	h.cs = newChunkState(h.key, 0, h.flags)
	h.stackSize = 0
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
		if h.cs.bytesConsumed == chunkSize {
			cv := h.cs.node().chainingValue()
			totalChunks := h.cs.chunkCounter() + 1
			h.addChunkChainingValue(cv, totalChunks)
			h.cs = newChunkState(h.key, totalChunks, h.flags)
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

// ensure that Hasher implements hash.Hash
var _ hash.Hash = (*Hasher)(nil)
