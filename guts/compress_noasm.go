//go:build !amd64

package guts

func compressChunks(cvs *[MaxSIMD][8]uint32, buf *[MaxSIMD * ChunkSize]byte, n int, key *[8]uint32, counter uint64, flags uint32) {
	compressChunksGeneric(cvs, buf, n, key, counter, flags)
}

func compressParents(cvs *[MaxSIMD][8]uint32, n int, key *[8]uint32, flags uint32) {
	compressParentsGeneric(cvs, n, key, flags)
}

func compressBlocks(out *[MaxSIMD * BlockSize]byte, n Node) {
	compressBlocksGeneric(out, n)
}
