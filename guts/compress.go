package guts

import (
	"encoding/binary"
	"unsafe"
)

// Each platform provides three kernels:
//
//   - compressChunks stores the chaining values of the first n chunks of buf
//     in cvs.
//   - compressParents merges the first n pairs of cvs, storing the chaining
//     value of each pair's parent node in the first n elements of cvs.
//   - compressBlocks compresses MaxSIMD copies of a node with successive
//     counter values, storing the results in out.
//
// A kernel may process more nodes than requested, clobbering unused elements
// of cvs.

// CompressBuffer compresses up to MaxSIMD chunks in parallel and returns their
// root node.
func CompressBuffer(buf *[MaxSIMD * ChunkSize]byte, buflen int, key *[8]uint32, counter uint64, flags uint32) Node {
	if buflen <= ChunkSize {
		return CompressChunk(buf[:buflen], key, counter, flags)
	}
	var cvs [MaxSIMD][8]uint32
	numChunks := uint64(buflen / ChunkSize)
	compressChunks(&cvs, buf, int(numChunks), key, counter, flags)
	if rem := buflen % ChunkSize; rem != 0 {
		// the partial chunk must be compressed serially
		cvs[numChunks] = ChainingValue(CompressChunk(buf[buflen-rem:buflen], key, counter+numChunks, flags))
		numChunks++
	}
	return mergeSubtrees(&cvs, numChunks, key, flags)
}

// CompressChunk compresses a single chunk, returning its final (uncompressed)
// node.
func CompressChunk(chunk []byte, key *[8]uint32, counter uint64, flags uint32) Node {
	n := Node{
		CV:       *key,
		Counter:  counter,
		BlockLen: BlockSize,
		Flags:    flags | FlagChunkStart,
	}
	for len(chunk) > BlockSize {
		n.Block = BytesToWords([64]byte(chunk))
		chunk = chunk[BlockSize:]
		n.CV = ChainingValue(n)
		n.Flags &^= FlagChunkStart
	}
	// pad last block with zeros
	var block [BlockSize]byte
	n.BlockLen = uint32(copy(block[:], chunk))
	n.Block = BytesToWords(block)
	n.Flags |= FlagChunkEnd
	return n
}

// CompressBlocks compresses MaxSIMD copies of n with successive counter values,
// storing the results in out.
func CompressBlocks(out *[MaxSIMD * BlockSize]byte, n Node) {
	compressBlocks(out, n)
}

// mergeSubtrees merges numCVs chaining values, returning their root node.
func mergeSubtrees(cvs *[MaxSIMD][8]uint32, numCVs uint64, key *[8]uint32, flags uint32) Node {
	for numCVs > 2 {
		// an odd CV is carried up to the next level
		last := cvs[numCVs-1]
		compressParents(cvs, int(numCVs/2), key, flags)
		if numCVs%2 != 0 {
			cvs[numCVs/2] = last
		}
		numCVs = (numCVs + 1) / 2
	}
	return ParentNode(cvs[0], cvs[1], key, flags)
}

// On little-endian platforms, bytes and words can be converted by
// reinterpreting memory.
var littleEndian = binary.NativeEndian.Uint16([]byte{1, 0}) == 1

// BytesToWords converts an array of 64 bytes to an array of 16 words.
func BytesToWords(bytes [64]byte) (words [16]uint32) {
	if littleEndian {
		return *(*[16]uint32)(unsafe.Pointer(&bytes))
	}
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(bytes[4*i:])
	}
	return
}

// WordsToBytes converts an array of 16 words to an array of 64 bytes.
func WordsToBytes(words [16]uint32) (bytes [64]byte) {
	if littleEndian {
		return *(*[64]byte)(unsafe.Pointer(&words))
	}
	for i, w := range words {
		binary.LittleEndian.PutUint32(bytes[4*i:], w)
	}
	return
}
