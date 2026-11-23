package guts

//go:generate go run ../avo/gen_arm64.go -out compress_arm64.s

//go:noescape
func compressChunksNEON(cvs *[4][8]uint32, buf *[4 * ChunkSize]byte, key *[8]uint32, counter uint64, flags uint32)

//go:noescape
func compressParentsNEON(parents *[4][8]uint32, cvs *[8][8]uint32, key *[8]uint32, flags uint32)

//go:noescape
func compressChunks8NEON(cvs *[8][8]uint32, buf *[8 * ChunkSize]byte, key *[8]uint32, counter uint64, flags uint32)

//go:noescape
func compressParents8NEON(parents *[8][8]uint32, cvs *[16][8]uint32, key *[8]uint32, flags uint32)

//go:noescape
func compressBlocks8NEON(out *[8 * BlockSize]byte, block *[16]uint32, cv *[8]uint32, counter uint64, blockLen uint32, flags uint32)

//go:noescape
func compressNodeARM64(out *[16]uint32, cv *[8]uint32, block *[16]uint32, counter uint64, blockLen uint32, flags uint32)

//go:noescape
func compressChunkBlocksARM64(cv *[8]uint32, blocks *byte, n uint64, counter uint64, flags uint32)

func compressNode(out *[16]uint32, cv *[8]uint32, block *[16]uint32, counter uint64, blockLen uint32, flags uint32) {
	compressNodeARM64(out, cv, block, counter, blockLen, flags)
}

func compressChunkBlocks(cv *[8]uint32, blocks []byte, counter uint64, flags uint32) {
	compressChunkBlocksARM64(cv, &blocks[0], uint64(len(blocks)/BlockSize), counter, flags)
}

// The NEON kernels process 4 nodes at a time. A lone trailing node is cheaper
// to compress serially.

func compressChunks(cvs *[MaxSIMD][8]uint32, buf *[MaxSIMD * ChunkSize]byte, n int, key *[8]uint32, counter uint64, flags uint32) {
	for i := 0; i < n; i += 4 {
		if n-i == 1 {
			cvs[i] = ChainingValue(compressChunk(buf[i*ChunkSize:][:ChunkSize], key, counter+uint64(i), flags))
			break
		} else if n-i > 4 {
			compressChunks8NEON((*[8][8]uint32)(cvs[i:]), (*[8 * ChunkSize]byte)(buf[i*ChunkSize:]), key, counter+uint64(i), flags)
			i += 4
			continue
		}
		compressChunksNEON((*[4][8]uint32)(cvs[i:]), (*[4 * ChunkSize]byte)(buf[i*ChunkSize:]), key, counter+uint64(i), flags)
	}
}

func compressParents(cvs *[MaxSIMD][8]uint32, n int, key *[8]uint32, flags uint32) {
	// NOTE: parents are written to the same array their children are read
	// from, but always behind the children that have yet to be read.
	if n > 4 {
		compressParents8NEON((*[8][8]uint32)(cvs[:]), cvs, key, flags)
		return
	}
	for i := 0; i < n; i += 4 {
		if n-i == 1 {
			cvs[i] = ChainingValue(ParentNode(cvs[i*2], cvs[i*2+1], key, flags))
			break
		}
		compressParentsNEON((*[4][8]uint32)(cvs[i:]), (*[8][8]uint32)(cvs[i*2:]), key, flags)
	}
}

func compressBlocks(out *[MaxSIMD * BlockSize]byte, n Node) {
	for i := 0; i < MaxSIMD; i += 8 {
		compressBlocks8NEON((*[8 * BlockSize]byte)(out[i*BlockSize:]), &n.Block, &n.CV, n.Counter+uint64(i), n.BlockLen, n.Flags)
	}
}
