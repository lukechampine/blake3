package main

import (
	"fmt"
)

func permute(m *[16]uint32) {
	*m = [16]uint32{
		m[2], m[6], m[3], m[10],
		m[7], m[0], m[4], m[13],
		m[1], m[11], m[12], m[5],
		m[9], m[14], m[15], m[8],
	}
}

func main() {

	var m [16]uint32

	for i := range m {
		m[i] = uint32(i)
	}
	for x := 1; x < 8; x++ {
		fmt.Printf(`// round%d
		
	// Mix the columns.
	s0, s4, s8, s12 = g(s0, s4, s8, s12, n.block[%d], n.block[%d])
	s1, s5, s9, s13 = g(s1, s5, s9, s13, n.block[%d], n.block[%d])
	s2, s6, s10, s14 = g(s2, s6, s10, s14, n.block[%d], n.block[%d])
	s3, s7, s11, s15 = g(s3, s7, s11, s15, n.block[%d], n.block[%d])

	// Mix the diagonals.
	s0, s5, s10, s15 = g(s0, s5, s10, s15, n.block[%d], n.block[%d])
	s1, s6, s11, s12 = g(s1, s6, s11, s12, n.block[%d], n.block[%d])
	s2, s7, s8, s13 = g(s2, s7, s8, s13, n.block[%d], n.block[%d])
	s3, s4, s9, s14 = g(s3, s4, s9, s14, n.block[%d], n.block[%d])
`, x,
			m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15])
		permute(&m)
	}
}
