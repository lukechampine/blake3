package guts

import (
	"math/bits"
)

func compressNodeGeneric(n *Node) (out [16]uint32) {
	g := func(a, b, c, d, mx, my uint32) (uint32, uint32, uint32, uint32) {
		a = a + mx + b
		d = bits.RotateLeft32(d^a, -16)
		c += d
		b = bits.RotateLeft32(b^c, -12)
		a = a + my + b
		d = bits.RotateLeft32(d^a, -8)
		c += d
		b = bits.RotateLeft32(b^c, -7)
		return a, b, c, d
	}

	// NOTE: we unroll all of the rounds, as well as the permutations that occur
	// between rounds.

	// round 1 (also initializes state)
	// columns
	s0, s4, s8, s12 := g(n.CV[0], n.CV[4], IV[0], uint32(n.Counter), n.Block[0], n.Block[1])
	s1, s5, s9, s13 := g(n.CV[1], n.CV[5], IV[1], uint32(n.Counter>>32), n.Block[2], n.Block[3])
	s2, s6, s10, s14 := g(n.CV[2], n.CV[6], IV[2], n.BlockLen, n.Block[4], n.Block[5])
	s3, s7, s11, s15 := g(n.CV[3], n.CV[7], IV[3], n.Flags, n.Block[6], n.Block[7])
	// diagonals
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.Block[8], n.Block[9])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.Block[10], n.Block[11])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.Block[12], n.Block[13])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.Block[14], n.Block[15])

	// round 2
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.Block[2], n.Block[6])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.Block[3], n.Block[10])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.Block[7], n.Block[0])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.Block[4], n.Block[13])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.Block[1], n.Block[11])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.Block[12], n.Block[5])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.Block[9], n.Block[14])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.Block[15], n.Block[8])

	// round 3
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.Block[3], n.Block[4])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.Block[10], n.Block[12])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.Block[13], n.Block[2])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.Block[7], n.Block[14])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.Block[6], n.Block[5])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.Block[9], n.Block[0])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.Block[11], n.Block[15])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.Block[8], n.Block[1])

	// round 4
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.Block[10], n.Block[7])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.Block[12], n.Block[9])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.Block[14], n.Block[3])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.Block[13], n.Block[15])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.Block[4], n.Block[0])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.Block[11], n.Block[2])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.Block[5], n.Block[8])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.Block[1], n.Block[6])

	// round 5
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.Block[12], n.Block[13])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.Block[9], n.Block[11])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.Block[15], n.Block[10])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.Block[14], n.Block[8])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.Block[7], n.Block[2])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.Block[5], n.Block[3])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.Block[0], n.Block[1])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.Block[6], n.Block[4])

	// round 6
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.Block[9], n.Block[14])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.Block[11], n.Block[5])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.Block[8], n.Block[12])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.Block[15], n.Block[1])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.Block[13], n.Block[3])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.Block[0], n.Block[10])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.Block[2], n.Block[6])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.Block[4], n.Block[7])

	// round 7
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.Block[11], n.Block[15])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.Block[5], n.Block[0])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.Block[1], n.Block[9])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.Block[8], n.Block[6])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.Block[14], n.Block[10])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.Block[2], n.Block[12])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.Block[3], n.Block[4])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.Block[7], n.Block[13])

	// finalization
	return [16]uint32{
		s0 ^ s8, s1 ^ s9, s2 ^ s10, s3 ^ s11,
		s4 ^ s12, s5 ^ s13, s6 ^ s14, s7 ^ s15,
		s8 ^ n.CV[0], s9 ^ n.CV[1], s10 ^ n.CV[2], s11 ^ n.CV[3],
		s12 ^ n.CV[4], s13 ^ n.CV[5], s14 ^ n.CV[6], s15 ^ n.CV[7],
	}
}

func compressChunksGeneric(cvs *[MaxSIMD][8]uint32, buf *[MaxSIMD * ChunkSize]byte, n int, key *[8]uint32, counter uint64, flags uint32) {
	for i := range cvs[:n] {
		cvs[i] = ChainingValue(CompressChunk(buf[i*ChunkSize:][:ChunkSize], key, counter+uint64(i), flags))
	}
}

func compressParentsGeneric(cvs *[MaxSIMD][8]uint32, n int, key *[8]uint32, flags uint32) {
	for i := range cvs[:n] {
		cvs[i] = ChainingValue(ParentNode(cvs[i*2], cvs[i*2+1], key, flags))
	}
}

func compressBlocksGeneric(out *[MaxSIMD * BlockSize]byte, n Node) {
	for i := 0; i < len(out); i += BlockSize {
		*(*[BlockSize]byte)(out[i:]) = WordsToBytes(CompressNode(n))
		n.Counter++
	}
}
