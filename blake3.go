// Package blake3 implements the BLAKE3 cryptographic hash function.
//
// This is a direct port of the Rust reference implementation. It is not
// optimized for performance.
package blake3

import (
	"encoding/binary"
	"hash"
)

const (
	blockLen = 64
	chunkLen = 1024
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

func g(state *[16]uint32, a, b, c, d int, mx, my uint32) {
	rotr := func(x uint32, n int) uint32 {
		return (x >> n) | (x << (32 - n))
	}
	state[a] = state[a] + state[b] + mx
	state[d] = rotr(state[d]^state[a], 16)
	state[c] = state[c] + state[d]
	state[b] = rotr(state[b]^state[c], 12)
	state[a] = state[a] + state[b] + my
	state[d] = rotr(state[d]^state[a], 8)
	state[c] = state[c] + state[d]
	state[b] = rotr(state[b]^state[c], 7)
}

func round(state, m *[16]uint32) {
	// Mix the columns.
	g(state, 0, 4, 8, 12, m[0], m[1])
	g(state, 1, 5, 9, 13, m[2], m[3])
	g(state, 2, 6, 10, 14, m[4], m[5])
	g(state, 3, 7, 11, 15, m[6], m[7])
	// Mix the diagonals.
	g(state, 0, 5, 10, 15, m[8], m[9])
	g(state, 1, 6, 11, 12, m[10], m[11])
	g(state, 2, 7, 8, 13, m[12], m[13])
	g(state, 3, 4, 9, 14, m[14], m[15])
}

func permute(m *[16]uint32) {
	permuted := [16]uint32{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}
	for i := range permuted {
		permuted[i] = m[permuted[i]]
	}
	*m = permuted
}

func compress(cv [8]uint32, block [16]uint32, counter uint64, blockLen uint32, flags uint32) [16]uint32 {
	state := [16]uint32{
		cv[0], cv[1], cv[2], cv[3],
		cv[4], cv[5], cv[6], cv[7],
		iv[0], iv[1], iv[2], iv[3],
		uint32(counter), uint32(counter >> 32), blockLen, flags,
	}

	round(&state, &block) // round 1
	permute(&block)
	round(&state, &block) // round 2
	permute(&block)
	round(&state, &block) // round 3
	permute(&block)
	round(&state, &block) // round 4
	permute(&block)
	round(&state, &block) // round 5
	permute(&block)
	round(&state, &block) // round 6
	permute(&block)
	round(&state, &block) // round 7

	for i := range cv {
		state[i] ^= state[i+8]
		state[i+8] ^= cv[i]
	}
	return state
}

func first8(words [16]uint32) (out [8]uint32) {
	copy(out[:], words[:8])
	return
}

func bytesToWords(bytes []byte, words []uint32) {
	for i := 0; i < len(bytes); i += 4 {
		words[i/4] = binary.LittleEndian.Uint32(bytes[i:])
	}
}

func wordsToBlock(words []uint32, bytes []byte) {
	for i, w := range words {
		binary.LittleEndian.PutUint32(bytes[i*4:], w)
	}
}

// Each chunk or parent node can produce either an 8-word chaining value or, by
// setting flagRoot, any number of final output bytes. The output struct
// captures the state just prior to choosing between those two possibilities.
type output struct {
	inChain    [8]uint32
	blockWords [16]uint32
	counter    uint64
	blockLen   uint32
	flags      uint32
}

func (o *output) chainingValue() [8]uint32 {
	return first8(compress(o.inChain, o.blockWords, o.counter, o.blockLen, o.flags))
}

// An OutputReader produces an unbounded stream of output from its initial
// state.
type OutputReader struct {
	o            *output
	block        [blockLen]byte
	remaining    int
	blocksoutput uint64
}

// Read implements io.Reader. Read always return len(p), nil.
func (or *OutputReader) Read(p []byte) (int, error) {
	lenp := len(p)
	for len(p) > 0 {
		if or.remaining == 0 {
			words := compress(
				or.o.inChain,
				or.o.blockWords,
				or.blocksoutput,
				or.o.blockLen,
				or.o.flags|flagRoot,
			)
			wordsToBlock(words[:], or.block[:])
			or.remaining = blockLen
			or.blocksoutput++
		}

		// copy from output buffer
		n := copy(p, or.block[blockLen-or.remaining:])
		or.remaining -= n
		p = p[n:]
	}
	return lenp, nil
}

type chunkState struct {
	chainingValue [8]uint32
	chunkCounter  uint64
	block         [blockLen]byte
	blockLen      int
	bytesConsumed int
	flags         uint32
}

func (cs *chunkState) update(input []byte) {
	for len(input) > 0 {
		// If the block buffer is full, compress it and clear it. More
		// input is coming, so this compression is not flagChunkEnd.
		if cs.blockLen == blockLen {
			var blockWords [16]uint32
			bytesToWords(cs.block[:], blockWords[:])
			cs.chainingValue = first8(compress(
				cs.chainingValue,
				blockWords,
				cs.chunkCounter,
				blockLen,
				cs.flags,
			))
			cs.block = [blockLen]byte{}
			cs.blockLen = 0
			// After the first chunk has been compressed, clear the start flag.
			cs.flags &^= flagChunkStart
		}

		// Copy input bytes into the block buffer.
		n := copy(cs.block[cs.blockLen:], input)
		cs.blockLen += n
		cs.bytesConsumed += n
		input = input[n:]
	}
}

func (cs *chunkState) output() *output {
	var blockWords [16]uint32
	bytesToWords(cs.block[:], blockWords[:])
	return &output{
		inChain:    cs.chainingValue,
		blockWords: blockWords,
		blockLen:   uint32(cs.blockLen),
		counter:    cs.chunkCounter,
		flags:      cs.flags | flagChunkEnd,
	}
}

func newChunkState(key [8]uint32, chunkCounter uint64, flags uint32) chunkState {
	return chunkState{
		chainingValue: key,
		chunkCounter:  chunkCounter,
		// compress the first chunk with the start flag set
		flags: flags | flagChunkStart,
	}
}

func parentOutput(left, right [8]uint32, key [8]uint32, flags uint32) *output {
	var blockWords [16]uint32
	copy(blockWords[:8], left[:])
	copy(blockWords[8:], right[:])
	return &output{
		inChain:    key,
		blockWords: blockWords,
		counter:    0,        // Always 0 for parent nodes.
		blockLen:   blockLen, // Always blockLen (64) for parent nodes.
		flags:      flagParent | flags,
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

// NewFromDerivedKey returns a Hasher whose key was derived from the supplied
// context string.
func NewFromDerivedKey(size int, ctx string) *Hasher {
	const (
		derivedKeyLen = 32
	)
	h := newHasher(iv, flagDeriveKeyContext, derivedKeyLen)
	h.Write([]byte(ctx))
	key := h.Sum(nil)
	var keyWords [8]uint32
	bytesToWords(key, keyWords[:])
	return newHasher(keyWords, flagDeriveKeyMaterial, size)
}

func (h *Hasher) addChunkChainingValue(cv [8]uint32, totalChunks uint64) {
	// This chunk might complete some subtrees. For each completed subtree,
	// its left child will be the current top entry in the CV stack, and
	// its right child will be the current value of `cv`. Pop each left
	// child off the stack, merge it with `cv`, and overwrite `cv`
	// with the result. After all these merges, push the final value of
	// `cv` onto the stack. The number of completed subtrees is given
	// by the number of trailing 0-bits in the new total number of chunks.
	right := cv
	for totalChunks&1 == 0 {
		// pop
		h.stackSize--
		left := h.chainStack[h.stackSize]
		// merge
		right = parentOutput(left, right, h.key, h.flags).chainingValue()
		totalChunks >>= 1
	}
	h.chainStack[h.stackSize] = right
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
			cv := h.cs.output().chainingValue()
			totalChunks := h.cs.chunkCounter + 1
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
	out := make([]byte, h.Size())
	h.XOF().Read(out)
	return append(b, out...)
}

// XOF returns an OutputReader initialized with the current hash state.
func (h *Hasher) XOF() *OutputReader {
	// Starting with the output from the current chunk, compute all the
	// parent chaining values along the right edge of the tree, until we
	// have the root output.
	output := h.cs.output()
	for i := h.stackSize - 1; i >= 0; i-- {
		output = parentOutput(
			h.chainStack[i],
			output.chainingValue(),
			h.key,
			h.flags,
		)
	}
	return &OutputReader{
		o: output,
	}
}

// ensure that Hasher implements hash.Hash
var _ hash.Hash = (*Hasher)(nil)
