// Package blake3 implements the BLAKE3 cryptographic hash function.
//
// This is a direct port of the Rust reference implementation. It is not
// optimized for performance.
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
	chunkLen  = 1024
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

// Each chunk or parent node can produce either an 8-word chaining value or, by
// setting flagRoot, any number of final output bytes. The node struct
// captures the state just prior to choosing between those two possibilities.
type node struct {
	cv       [8]uint32
	block    [16]uint32
	counter  uint64
	blockLen uint32
	flags    uint32
}

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

func (n node) chainingValue() (cv [8]uint32) {
	full := n.compress()
	copy(cv[:], full[:8])
	return
}

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

// An OutputReader produces an seekable stream of 2^64 - 1 output bytes.
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

type chunkState struct {
	n             node
	block         [blockSize]byte
	blockLen      int
	bytesConsumed int
}

func (cs *chunkState) chunkCounter() uint64 {
	return cs.n.counter
}

func (cs *chunkState) update(input []byte) {
	for len(input) > 0 {
		// If the block buffer is full, compress it and clear it. More
		// input is coming, so this compression is not flagChunkEnd.
		if cs.blockLen == blockSize {
			bytesToWords(cs.block[:], cs.n.block[:])
			cs.n.cv = cs.n.chainingValue()
			cs.block = [blockSize]byte{}
			cs.blockLen = 0
			// After the first chunk has been compressed, clear the start flag.
			cs.n.flags &^= flagChunkStart
		}

		// Copy input bytes into the block buffer.
		n := copy(cs.block[cs.blockLen:], input)
		cs.blockLen += n
		cs.bytesConsumed += n
		input = input[n:]
	}
}

func (cs *chunkState) node() node {
	n := cs.n
	bytesToWords(cs.block[:], n.block[:])
	n.blockLen = uint32(cs.blockLen)
	n.flags |= flagChunkEnd
	return n
}

func newChunkState(key [8]uint32, chunkCounter uint64, flags uint32) chunkState {
	return chunkState{
		n: node{
			cv:       key,
			counter:  chunkCounter,
			blockLen: blockSize,
			// compress the first chunk with the start flag set
			flags: flags | flagChunkStart,
		},
	}
}

func parentNode(left, right [8]uint32, key [8]uint32, flags uint32) node {
	var blockWords [16]uint32
	copy(blockWords[:8], left[:])
	copy(blockWords[8:], right[:])
	return node{
		cv:       key,
		block:    blockWords,
		counter:  0,         // Always 0 for parent nodes.
		blockLen: blockSize, // Always blockSize (64) for parent nodes.
		flags:    flags | flagParent,
	}
}

// Hasher implements hash.Hash.
type Hasher struct {
	cs         chunkState
	key        [8]uint32
	chainStack [54][8]uint32 // space for 54 subtrees (2^54 * chunkLen = 2^64)
	stackSize  int           // index within chainStack
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

func (h *Hasher) addChunkChainingValue(cv [8]uint32, totalChunks uint64) {
	// This chunk might complete some subtrees. For each completed subtree,
	// its left child will be the current top entry in the CV stack, and
	// its right child will be the current value of `cv`. Pop each left
	// child off the stack, merge it with `cv`, and overwrite `cv`
	// with the result. After all these merges, push the final value of
	// `cv` onto the stack. The number of completed subtrees is given
	// by the number of trailing 0-bits in the new total number of chunks.
	for totalChunks&1 == 0 {
		// pop and merge
		h.stackSize--
		cv = parentNode(h.chainStack[h.stackSize], cv, h.key, h.flags).chainingValue()
		totalChunks >>= 1
	}
	h.chainStack[h.stackSize] = cv
	h.stackSize++
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
		// If the current chunk is complete, finalize it and reset the
		// chunk state. More input is coming, so this chunk is not flagRoot.
		if h.cs.bytesConsumed == chunkLen {
			cv := h.cs.node().chainingValue()
			totalChunks := h.cs.chunkCounter() + 1
			h.addChunkChainingValue(cv, totalChunks)
			h.cs = newChunkState(h.key, totalChunks, h.flags)
		}

		// Compress input bytes into the current chunk state.
		n := chunkLen - h.cs.bytesConsumed
		if n > len(p) {
			n = len(p)
		}
		h.cs.update(p[:n])
		p = p[n:]
	}
	return lenp, nil
}

// Sum implements hash.Hash.
func (h *Hasher) Sum(b []byte) []byte {
	ret, fill := sliceForAppend(b, h.Size())
	h.XOF().Read(fill)
	return ret
}

// XOF returns an OutputReader initialized with the current hash state.
func (h *Hasher) XOF() *OutputReader {
	// Starting with the node from the current chunk, compute all the
	// parent chaining values along the right edge of the tree, until we
	// have the root node.
	n := h.cs.node()
	for i := h.stackSize - 1; i >= 0; i-- {
		n = parentNode(h.chainStack[i], n.chainingValue(), h.key, h.flags)
	}
	n.flags |= flagRoot
	return &OutputReader{
		n: n,
	}
}

// Sum256 returns the unkeyed BLAKE3 hash of b, truncated to 256 bits.
func Sum256(b []byte) [32]byte {
	var out [32]byte
	h := New(32, nil)
	h.Write(b)
	h.Sum(out[:0])
	return out
}

// Sum512 returns the unkeyed BLAKE3 hash of b, truncated to 512 bits.
func Sum512(b []byte) [64]byte {
	var out [64]byte
	h := New(64, nil)
	h.Write(b)
	h.Sum(out[:0])
	return out
}

// DeriveKey derives a subkey from ctx and srcKey.
func DeriveKey(subKey []byte, ctx string, srcKey []byte) {
	// construct the derivation Hasher
	const derivationIVLen = 32
	h := newHasher(iv, flagDeriveKeyContext, 32)
	h.Write([]byte(ctx))
	var derivationIV [8]uint32
	bytesToWords(h.Sum(make([]byte, 0, derivationIVLen)), derivationIV[:])
	h = newHasher(derivationIV, flagDeriveKeyMaterial, len(subKey))
	// derive the subKey
	h.Write(srcKey)
	h.Sum(subKey[:0])
}

// ensure that Hasher implements hash.Hash
var _ hash.Hash = (*Hasher)(nil)

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
