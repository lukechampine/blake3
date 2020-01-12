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
	s[0], s[4], s[8], s[12] = g(s[0], s[4], s[8], s[12], n.block[%d], n.block[%d])
	s[1], s[5], s[9], s[13] = g(s[1], s[5], s[9], s[13], n.block[%d], n.block[%d])
	s[2], s[6], s[10], s[14] = g(s[2], s[6], s[10], s[14], n.block[%d], n.block[%d])
	s[3], s[7], s[11], s[15] = g(s[3], s[7], s[11], s[15], n.block[%d], n.block[%d])

	// Mix the diagonals.
	s[0], s[5], s[10], s[15] = g(s[0], s[5], s[10], s[15], n.block[%d], n.block[%d])
	s[1], s[6], s[11], s[12] = g(s[1], s[6], s[11], s[12], n.block[%d], n.block[%d])
	s[2], s[7], s[8], s[13] = g(s[2], s[7], s[8], s[13], n.block[%d], n.block[%d])
	s[3], s[4], s[9], s[14] = g(s[3], s[4], s[9], s[14], n.block[%d], n.block[%d])
`, x,
			m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15])
		permute(&m)
	}
}
