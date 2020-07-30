package blake3

import (
	"bytes"
	"math/bits"
)

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

func compressNodeGeneric(out *[16]uint32, n node) {
	// NOTE: we unroll all of the rounds, as well as the permutations that occur
	// between rounds.

	// round 1 (also initializes state)
	// columns
	s0, s4, s8, s12 := g(n.cv[0], n.cv[4], iv[0], uint32(n.counter), n.block[0], n.block[1])
	s1, s5, s9, s13 := g(n.cv[1], n.cv[5], iv[1], uint32(n.counter>>32), n.block[2], n.block[3])
	s2, s6, s10, s14 := g(n.cv[2], n.cv[6], iv[2], n.blockLen, n.block[4], n.block[5])
	s3, s7, s11, s15 := g(n.cv[3], n.cv[7], iv[3], n.flags, n.block[6], n.block[7])
	// diagonals
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[8], n.block[9])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[10], n.block[11])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[12], n.block[13])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[14], n.block[15])

	// round 2
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[2], n.block[6])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[3], n.block[10])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[7], n.block[0])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[4], n.block[13])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[1], n.block[11])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[12], n.block[5])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[9], n.block[14])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[15], n.block[8])

	// round 3
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[3], n.block[4])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[10], n.block[12])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[13], n.block[2])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[7], n.block[14])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[6], n.block[5])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[9], n.block[0])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[11], n.block[15])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[8], n.block[1])

	// round 4
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[10], n.block[7])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[12], n.block[9])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[14], n.block[3])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[13], n.block[15])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[4], n.block[0])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[11], n.block[2])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[5], n.block[8])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[1], n.block[6])

	// round 5
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[12], n.block[13])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[9], n.block[11])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[15], n.block[10])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[14], n.block[8])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[7], n.block[2])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[5], n.block[3])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[0], n.block[1])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[6], n.block[4])

	// round 6
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[9], n.block[14])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[11], n.block[5])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[8], n.block[12])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[15], n.block[1])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[13], n.block[3])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[0], n.block[10])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[2], n.block[6])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[4], n.block[7])

	// round 7
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[11], n.block[15])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[5], n.block[0])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[1], n.block[9])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[8], n.block[6])
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[14], n.block[10])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[2], n.block[12])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[3], n.block[4])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[7], n.block[13])

	// finalization
	*out = [16]uint32{
		s0 ^ s8, s1 ^ s9, s2 ^ s10, s3 ^ s11,
		s4 ^ s12, s5 ^ s13, s6 ^ s14, s7 ^ s15,
		s8 ^ n.cv[0], s9 ^ n.cv[1], s10 ^ n.cv[2], s11 ^ n.cv[3],
		s12 ^ n.cv[4], s13 ^ n.cv[5], s14 ^ n.cv[6], s15 ^ n.cv[7],
	}
}

func compressBufferGeneric(buf *[8192]byte, buflen int, key *[8]uint32, counter uint64, flags uint32) (n node) {
	if buflen <= chunkSize {
		return compressChunk(buf[:buflen], key, counter, flags)
	}
	cvs := make([][8]uint32, 0, 8)
	for bb := bytes.NewBuffer(buf[:buflen]); bb.Len() > 0; {
		n := compressChunk(bb.Next(chunkSize), key, counter, flags)
		cvs = append(cvs, chainingValue(n))
		counter++
	}
	return mergeSubtrees(cvs, key, flags)
}

func chainingValue(n node) (cv [8]uint32) {
	full := compressNode(n)
	copy(cv[:], full[:])
	return
}

func mergeSubtrees(cvs [][8]uint32, key *[8]uint32, flags uint32) node {
	parent := func(l, r [8]uint32) [8]uint32 {
		return chainingValue(parentNode(l, r, *key, flags))
	}
	switch len(cvs) {
	case 8:
		cvs[6] = parent(cvs[6], cvs[7])
		fallthrough
	case 7:
		cvs[4], cvs[5] = parent(cvs[4], cvs[5]), cvs[6]
		fallthrough
	case 6:
		cvs[4] = parent(cvs[4], cvs[5])
		fallthrough
	case 5:
		fallthrough
	case 4:
		cvs[2] = parent(cvs[2], cvs[3])
		fallthrough
	case 3:
		cvs[0], cvs[1] = parent(cvs[0], cvs[1]), cvs[2]
	}
	if len(cvs) > 4 {
		cvs[0], cvs[1] = parent(cvs[0], cvs[1]), cvs[4]
	}
	return parentNode(cvs[0], cvs[1], *key, flags)
}
