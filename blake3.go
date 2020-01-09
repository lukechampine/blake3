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
	OUT_LEN   = 32
	KEY_LEN   = 32
	BLOCK_LEN = 64
	CHUNK_LEN = 1024

	CHUNK_START         = 1 << 0
	CHUNK_END           = 1 << 1
	PARENT              = 1 << 2
	ROOT                = 1 << 3
	KEYED_HASH          = 1 << 4
	DERIVE_KEY_CONTEXT  = 1 << 5
	DERIVE_KEY_MATERIAL = 1 << 6
)

var IV = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

var MSG_PERMUTATION = [16]uint{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

func rotate_right(x uint32, n int) uint32 {
	return (x >> n) | (x << (32 - n))
}

// The mixing function, G, which mixes either a column or a diagonal.
func g(state *[16]uint32, a, b, c, d int, mx, my uint32) {
	state[a] = state[a] + state[b] + mx
	state[d] = rotate_right(state[d]^state[a], 16)
	state[c] = state[c] + state[d]
	state[b] = rotate_right(state[b]^state[c], 12)
	state[a] = state[a] + state[b] + my
	state[d] = rotate_right(state[d]^state[a], 8)
	state[c] = state[c] + state[d]
	state[b] = rotate_right(state[b]^state[c], 7)
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
	var permuted [16]uint32
	for i := range permuted {
		permuted[i] = m[MSG_PERMUTATION[i]]
	}
	*m = permuted
}

func compress(chaining_value *[8]uint32, block_words *[16]uint32, counter uint64, block_len uint32, flags uint32) [16]uint32 {
	state := [16]uint32{
		chaining_value[0],
		chaining_value[1],
		chaining_value[2],
		chaining_value[3],
		chaining_value[4],
		chaining_value[5],
		chaining_value[6],
		chaining_value[7],
		IV[0],
		IV[1],
		IV[2],
		IV[3],
		uint32(counter),
		uint32(counter >> 32),
		block_len,
		flags,
	}
	block := *block_words

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

	for i := range chaining_value {
		state[i] ^= state[i+8]
		state[i+8] ^= chaining_value[i]
	}
	return state
}

func first_8_words(compression_output [16]uint32) (out [8]uint32) {
	copy(out[:], compression_output[:8])
	return
}

func words_from_litte_endian_bytes(bytes []byte, words []uint32) {
	for i := 0; i < len(bytes); i += 4 {
		words[i/4] = binary.LittleEndian.Uint32(bytes[i:])
	}
}

// Each chunk or parent node can produce either an 8-word chaining value or, by
// setting the ROOT flag, any number of final output bytes. The output struct
// captures the state just prior to choosing between those two possibilities.
type output struct {
	input_chaining_value [8]uint32
	block_words          [16]uint32
	counter              uint64
	block_len            uint32
	flags                uint32
}

func (o *output) chaining_value() [8]uint32 {
	return first_8_words(compress(
		&o.input_chaining_value,
		&o.block_words,
		o.counter,
		o.block_len,
		o.flags,
	))
}

func (o *output) root_output_bytes(out_slice []byte) {
	output_block_counter := uint64(0)
	for len(out_slice) > 0 {
		words := compress(
			&o.input_chaining_value,
			&o.block_words,
			output_block_counter,
			o.block_len,
			o.flags|ROOT,
		)
		var wordsBytes [16 * 4]byte
		for i, w := range words {
			binary.LittleEndian.PutUint32(wordsBytes[i*4:], w)
		}
		n := copy(out_slice, wordsBytes[:])
		out_slice = out_slice[n:]
		output_block_counter++
	}
}

type chunkState struct {
	chaining_value    [8]uint32
	chunk_counter     uint64
	block             [BLOCK_LEN]byte
	block_len         byte
	blocks_compressed byte
	flags             uint32
}

func (cs *chunkState) len() int {
	return BLOCK_LEN*int(cs.blocks_compressed) + int(cs.block_len)
}

func (cs *chunkState) start_flag() uint32 {
	if cs.blocks_compressed == 0 {
		return CHUNK_START
	}
	return 0
}

func (cs *chunkState) update(input []byte) {
	for len(input) > 0 {
		// If the block buffer is full, compress it and clear it. More
		// input is coming, so this compression is not CHUNK_END.
		if cs.block_len == BLOCK_LEN {
			var block_words [16]uint32
			words_from_litte_endian_bytes(cs.block[:], block_words[:])
			cs.chaining_value = first_8_words(compress(
				&cs.chaining_value,
				&block_words,
				cs.chunk_counter,
				BLOCK_LEN,
				cs.flags|cs.start_flag(),
			))
			cs.blocks_compressed++
			cs.block = [BLOCK_LEN]byte{}
			cs.block_len = 0
		}

		// Copy input bytes into the block buffer.
		n := copy(cs.block[cs.block_len:], input)
		cs.block_len += byte(n)
		input = input[n:]
	}
}

func (cs *chunkState) output() *output {
	var block_words [16]uint32
	words_from_litte_endian_bytes(cs.block[:], block_words[:])
	return &output{
		input_chaining_value: cs.chaining_value,
		block_words:          block_words,
		block_len:            uint32(cs.block_len),
		counter:              cs.chunk_counter,
		flags:                cs.flags | cs.start_flag() | CHUNK_END,
	}
}

func newChunkState(key [8]uint32, chunk_counter uint64, flags uint32) chunkState {
	return chunkState{
		chaining_value: key,
		chunk_counter:  chunk_counter,
		flags:          flags,
	}
}

func parent_output(left_child_cv [8]uint32, right_child_cv [8]uint32, key [8]uint32, flags uint32) *output {
	var block_words [16]uint32
	copy(block_words[:8], left_child_cv[:])
	copy(block_words[8:], right_child_cv[:])
	return &output{
		input_chaining_value: key,
		block_words:          block_words,
		counter:              0,         // Always 0 for parent nodes.
		block_len:            BLOCK_LEN, // Always BLOCK_LEN (64) for parent nodes.
		flags:                PARENT | flags,
	}
}

func parent_cv(left_child_cv [8]uint32, right_child_cv [8]uint32, key [8]uint32, flags uint32) [8]uint32 {
	return parent_output(left_child_cv, right_child_cv, key, flags).chaining_value()
}

// Hasher implements hash.Hash.
type Hasher struct {
	chunk_state  chunkState
	key          [8]uint32
	cv_stack     [54][8]uint32 // Space for 54 subtree chaining values:
	cv_stack_len byte          // 2^54 * CHUNK_LEN = 2^64
	flags        uint32
	out_size     int
}

func newHasher(key [8]uint32, flags uint32, out_size int) *Hasher {
	return &Hasher{
		chunk_state: newChunkState(key, 0, flags),
		key:         key,
		flags:       flags,
		out_size:    out_size,
	}
}

// New returns a Hasher for the specified size and key. If key is nil, the hash
// is unkeyed.
func New(size int, key []byte) *Hasher {
	if key == nil {
		return newHasher(IV, 0, size)
	}
	var key_words [8]uint32
	words_from_litte_endian_bytes(key[:], key_words[:])
	return newHasher(key_words, KEYED_HASH, size)
}

// NewFromDerivedKey returns a Hasher whose key was derived from the supplied
// context string.
func NewFromDerivedKey(size int, ctx string) *Hasher {
	h := newHasher(IV, DERIVE_KEY_CONTEXT, KEY_LEN)
	h.Write([]byte(ctx))
	key := h.Sum(nil)
	var key_words [8]uint32
	words_from_litte_endian_bytes(key, key_words[:])
	return newHasher(key_words, DERIVE_KEY_MATERIAL, size)
}

func (h *Hasher) push_stack(cv [8]uint32) {
	h.cv_stack[h.cv_stack_len] = cv
	h.cv_stack_len++
}

func (h *Hasher) pop_stack() [8]uint32 {
	h.cv_stack_len--
	return h.cv_stack[h.cv_stack_len]
}

func (h *Hasher) add_chunk_chaining_value(new_cv [8]uint32, total_chunks uint64) {
	// This chunk might complete some subtrees. For each completed subtree,
	// its left child will be the current top entry in the CV stack, and
	// its right child will be the current value of `new_cv`. Pop each left
	// child off the stack, merge it with `new_cv`, and overwrite `new_cv`
	// with the result. After all these merges, push the final value of
	// `new_cv` onto the stack. The number of completed subtrees is given
	// by the number of trailing 0-bits in the new total number of chunks.
	for total_chunks&1 == 0 {
		new_cv = parent_cv(h.pop_stack(), new_cv, h.key, h.flags)
		total_chunks >>= 1
	}
	h.push_stack(new_cv)
}

// Reset implements hash.Hash.
func (h *Hasher) Reset() {
	h.chunk_state = newChunkState(h.key, 0, h.flags)
	h.cv_stack_len = 0
}

// BlockSize implements hash.Hash.
func (h *Hasher) BlockSize() int { return 64 }

// Size implements hash.Hash.
func (h *Hasher) Size() int { return h.out_size }

// Write implements hash.Hash.
func (h *Hasher) Write(input []byte) (int, error) {
	written := len(input)
	for len(input) > 0 {
		// If the current chunk is complete, finalize it and reset the
		// chunk state. More input is coming, so this chunk is not ROOT.
		if h.chunk_state.len() == CHUNK_LEN {
			chunk_cv := h.chunk_state.output().chaining_value()
			total_chunks := h.chunk_state.chunk_counter + 1
			h.add_chunk_chaining_value(chunk_cv, total_chunks)
			h.chunk_state = newChunkState(h.key, total_chunks, h.flags)
		}

		// Compress input bytes into the current chunk state.
		n := len(input)
		if n > CHUNK_LEN-h.chunk_state.len() {
			n = CHUNK_LEN - h.chunk_state.len()
		}
		h.chunk_state.update(input[:n])
		input = input[n:]
	}
	return written, nil
}

// Sum implements hash.Hash.
func (h *Hasher) Sum(out_slice []byte) []byte {
	// Starting with the output from the current chunk, compute all the
	// parent chaining values along the right edge of the tree, until we
	// have the root output.
	var output = h.chunk_state.output()
	var parent_nodes_remaining = h.cv_stack_len
	for parent_nodes_remaining > 0 {
		parent_nodes_remaining--
		output = parent_output(
			h.cv_stack[parent_nodes_remaining],
			output.chaining_value(),
			h.key,
			h.flags,
		)
	}
	out := make([]byte, h.Size())
	output.root_output_bytes(out)
	return append(out_slice, out...)
}

// ensure that Hasher implements hash.Hash
var _ hash.Hash = (*Hasher)(nil)
