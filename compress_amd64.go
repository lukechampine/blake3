package blake3

import (
	"unsafe"

	"golang.org/x/sys/cpu"
)

//go:generate go run avo/gen.go -out blake3_amd64.s

//go:noescape
func compressChunksAVX2(cvs *[8][8]uint32, buf *[8192]byte, key *[8]uint32, counter uint64, flags uint32)

func compressNode(n node) (out [16]uint32) {
	compressNodeGeneric(&out, n)
	return
}

func compressBufferLarge(buf *[8192]byte, buflen int, key *[8]uint32, counter uint64, flags uint32) node {
	var cvs [8][8]uint32
	compressChunksAVX2(&cvs, buf, key, counter, flags)
	numChunks := uint64(buflen / chunkSize)
	if buflen%chunkSize != 0 {
		// use non-asm for remainder
		partialChunk := buf[buflen-buflen%chunkSize : buflen]
		cvs[numChunks] = chainingValue(compressChunk(partialChunk, key, counter+numChunks, flags))
		numChunks++
	}
	return mergeSubtrees(cvs[:numChunks], key, flags)
}

func compressBuffer(buf *[8192]byte, buflen int, key *[8]uint32, counter uint64, flags uint32) node {
	switch {
	case cpu.X86.HasAVX2 && buflen >= chunkSize*2:
		return compressBufferLarge(buf, buflen, key, counter, flags)
	default:
		return compressBufferGeneric(buf, buflen, key, counter, flags)
	}
}

func compressChunk(chunk []byte, key *[8]uint32, counter uint64, flags uint32) node {
	n := node{
		cv:       *key,
		counter:  counter,
		blockLen: blockSize,
		flags:    flags | flagChunkStart,
	}
	blockBytes := (*[64]byte)(unsafe.Pointer(&n.block))[:]
	for len(chunk) > blockSize {
		copy(blockBytes, chunk)
		chunk = chunk[blockSize:]
		n.cv = chainingValue(n)
		n.flags &^= flagChunkStart
	}
	// pad last block with zeros
	n.block = [16]uint32{}
	copy(blockBytes, chunk)
	n.blockLen = uint32(len(chunk))
	n.flags |= flagChunkEnd
	return n
}

func wordsToBytes(words [16]uint32, block *[64]byte) {
	*block = *(*[64]byte)(unsafe.Pointer(&words))
}

func hashBlock(out *[64]byte, buf []byte) {
	var block [16]uint32
	copy((*[64]byte)(unsafe.Pointer(&block))[:], buf)
	compressNodeGeneric((*[16]uint32)(unsafe.Pointer(out)), node{
		cv:       iv,
		block:    block,
		blockLen: uint32(len(buf)),
		flags:    flagChunkStart | flagChunkEnd | flagRoot,
	})
}
